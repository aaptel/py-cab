#!/usr/bin/env python3

import struct
import sys
from pprint import pprint as P
from collections import OrderedDict
import argparse
import zlib
import hashlib

def md5(buf):
    h = hashlib.md5()
    h.update(buf)
    return h.hexdigest()

def dump(buf):
    cab = CABFile(buf)
    cab.dump()
    print("\n\n\n")

    for i in range(len(cab.folders)):
        print("# Folder %d files"%i)
        files = cab.get_folder_files(i)
        for (fn, data) in files:
            cksum = md5(data)
            if len(data) > 10:
                data = "%s... (%d)"%(data[:10], len(data))
            print("%s : %s (MD5:%s)"%(fn, data, cksum))

def main():
    if len(sys.argv) < 2:
        print("Usage: cab.py [xcz] ...")
        exit(1)

    op, args = sys.argv[1], sys.argv[2:]
    if 'x' in op:
        dump(open(args[0], "rb").read())
    elif 'c' in op:
        layout = [[[b"fichierrrrr", b"A"*40000]]]
        buf = make_cab(layout, compress=('z' in op))
        fn='/tmp/cabtest'
        open(fn, "wb+").write(buf)
        print("wrote %s"%fn)

        print("\n\n")
        dump(buf)

# <     little-endian
# >     big-endian
# x     pad byte  no value
# c     char      bytes of length 1        1
# b     schar     integer                  1
# B     uchar     integer                  1
# h     short     integer                  2
# H     ushort    integer                  2
# i     int       integer                  4
# I     uint      integer                  4
# l     long      integer                  4
# L     ulong     integer                  4
# q     ll        integer                  8
# Q     ull       integer                  8
# f     float     float                    4
# d     double    float                    8
# s     char[]    bytes

class CABFile:
    COMPRESSION_NONE    = 0
    COMPRESSION_MSZIP   = 1
    COMPRESSION_QUANTUM = 2
    COMPRESSION_LZX     = 3

    def __init__(self, buf):
        self.buf = buf
        self.f = Blob(buf)
        self.folders = []
        self.files = []
        self.datas = []
        self.data_off = {}

        self.f.parse('4s', 'signature')
        self.f.parse('xxxx')
        self.f.parse('<I', 'cbCabinet')
        self.f.parse('xxxx')
        self.f.parse('<I', 'coffFiles')
        self.f.parse('xxxx')
        self.f.parse('<B', 'vMinor')
        self.f.parse('<B', 'vMajor')
        self.f.parse('<H', 'cFolders')
        self.f.parse('<H', 'cFiles')
        self.f.parse('<H', 'flags')
        self.f.parse('<H', 'setID')
        self.f.parse('<H', 'iCabinet')
        if self.f.data['flags'] & 0x0004 != 0:
            self.f.parse('<H', 'cbCFHeader')
            self.f.parse('<B', 'cbCFFolder')
            self.f.parse('<B', 'cbCFData')
        if self.f.data['flags'] & 0x0001 != 0:
            self.f.parse_cstring('szCabinetPrev')
            self.f.parse_cstring('szDiskPrev')
        if self.f.data['flags'] & 0x0002 != 0:
            self.f.parse_cstring('szCabinetNext')
            self.f.parse_cstring('szDiskNext')

        Hres = self.f.data.get('cbCFHeader', 0)
        Fres = self.f.data.get('cbCFFolder', 0)
        Dres = self.f.data.get('cbCFData', 0)

        self.f.parse('%ds'%Hres, 'abReserve')

        for i in range(self.f.data['cFolders']):
            b = self.f.new_blob()
            b.parse('<I', 'coffCabStart')
            b.parse('<H', 'cCFData')
            b.parse('<H', 'typeCompress')
            b.parse('%ds'%Fres, 'abReserve')
            self.folders.append(b)
            self.f.br.off += b.read_size()

        for i in range(self.f.data['cFiles']):
            b = self.f.new_blob()
            b.parse('<I', 'cbFile')
            b.parse('<I', 'uoffFolderStart')
            b.parse('<H', 'iFolder')
            b.parse('<H', 'date')
            b.parse('<H', 'time')
            b.parse('<H', 'attribs')
            b.parse_cstring('szName')
            self.files.append(b)
            self.f.br.off += b.read_size()

        while self.f.br.off < len(self.f.br.buf):
            b = self.f.new_blob()
            b.parse('<I', 'csum')
            b.parse('<H', 'cbData')
            b.parse('<H', 'cbUncomp')
            b.parse('%ds'%Dres, 'abReserve')
            b.parse('%ds'%b.data['cbData'], 'ab')
            self.datas.append(b)
            self.data_off[self.f.read_size()] = b
            self.f.br.off += b.read_size()

    def dump(self):
        self.f.dump()

        for (i,fol) in enumerate(self.folders):
            print("\n# FOLDER %d"%i)
            fol.dump()

        for (i,fil) in enumerate(self.files):
            print("\n# FILES %d"%i)
            fil.dump()

        for (i,dat) in enumerate(self.datas):
            print("\n# DATA %d"%i)
            dat.dump()

    def get_folder_files(self, index):
        chunks = []
        folder = self.folders[index]
        cdata_off = folder.data['coffCabStart']
        cdata_nb = folder.data['cCFData']
        compress = folder.data['typeCompress']

        # get all CDATA belonging to that folder

        for i in range(cdata_nb):
            cdata = self.data_off[cdata_off]
            raw = cdata.data['ab']

            # checksum happens on whole CDATA block minus initial 4 bytes (csum itself)
            csum = checksum(cdata.br.buf[4:cdata.read_size()])
            assert(csum == cdata.data['csum'])

            chunks.append(raw)
            cdata_off += cdata.read_size()


        # concat them, apply eventual decompress step

        folder_data = None
        if compress == CABFile.COMPRESSION_NONE:
            folder_data = b''.join(chunks)
        elif compress == CABFile.COMPRESSION_MSZIP:
            folder_data = decompress_mzip(chunks)
        else:
            assert(False and "unsupported type")

        # split the folder data according to offsets set in CFILEs

        files = []
        for fi in self.files:
            if fi.data['iFolder'] == index:
                beg = fi.data['uoffFolderStart']
                end = beg + fi.data['cbFile']
                data = folder_data[beg:end]
                files.append((fi.data['szName'], data))

        return files

def decompress_mzip(chunks):
    # remove 'CK' bytes from each CDATA buffer
    chunks = [x[2:] for x in chunks]
    output_chunks = []

    for i, c in enumerate(chunks):
        # https://blogs.kde.org/2008/01/04/kcabinet-mostly-working
        if i == 0:
            d = zlib.decompressobj(-15, zdict=b'')
        else:
            d = zlib.decompressobj(-15, zdict=output_chunks[i-1])
        output_chunks.append(d.decompress(c))

    return b''.join(output_chunks)

def checksum(buf, seed=0):
    size = len(buf)
    last = (size // 4)*4
    # walk buf 4 bytes at a time to work on longs
    for i in range(0, last, 4):
        seed ^= ((buf[i+0]) | (buf[i+1]<<8) | (buf[i+2]<<16) | (buf[i+3]<<24))

    # handle uncomplete long at the end
    rest = size % 4
    if rest == 1:
        seed ^= buf[last]
    if rest == 2:
        seed ^= ((buf[last]<<8)|(buf[last+1]))
    if rest == 3:
        seed ^= ((buf[last]<<16)|(buf[last+1]<<8)|(buf[last+2]))

    return seed

class BinReader:
    def __init__(self, buf, off=0):
        self.buf = buf
        self.off = off

    def read(self, fmt):
        r = struct.unpack_from(fmt, self.buf, self.off)
        self.off += struct.calcsize(fmt)
        return r

    def read_cstring(self):
        s = b''
        while True:
            r = self.read('B')
            if int(r[0]) == 0:
                return (s,)
            s += bytes(r)

class BinWriter:
    def __init__(self):
        self.buf = bytearray(b'')
        self.off = 0

    def write(self, fmt, *args):
        self.buf += struct.pack(fmt, *args)
        self.off = len(self.buf)

    def write_at(self, off, fmt, *args):
        struct.pack_into(fmt, self.buf, off, *args)

    def append(self, buf):
        self.buf += buf
        self.off = len(self.buf)

class Blob:
    def __init__(self, buf):
        self.br = BinReader(buf)
        self.data = OrderedDict({})

    def read_size(self):
        return self.br.off

    def parse(self, fmt, name=None):
        r = self.br.read(fmt)
        if name is None:
            return
        self.data[name] = r[0]

    def parse_cstring(self, name):
        r = self.br.read_cstring()
        if name is None:
            return
        self.data[name] = r[0]

    def new_blob(self):
        return Blob(self.br.buf[self.br.off:])

    def dump(self):
        for k,v in self.data.items():
            if type(v) in [str, bytes]:
                if len(v) > 30:
                    v = '%s... (%d bytes)'%(v[0:30], len(v))
            print("%-20.20s %s"%(k, v))


def make_cdatas(data, compress=True):
    start_off = 0
    max_chunk_size = 32768
    data_size = len(data)
    remaining = data_size
    res = []
    z = zlib.compressobj(wbits=-15)

    while start_off < data_size:
        output = BinWriter()

        chunk_size = min(max_chunk_size, remaining)
        chunk = data[start_off:start_off+chunk_size]

        output.write('<I', 0)

        if compress:
            c = b'CK'+z.compress(chunk)
            c += z.flush(zlib.Z_FINISH if chunk_size == remaining else zlib.Z_FULL_FLUSH)
        else:
            c = chunk

        output.write('<HH', len(c), len(chunk))
        output.append(c)
        csum = checksum(output.buf[4:])
        print("csum = %d"%csum)
        output.write_at(0, '<I', csum)
        res.append(output.buf)

        start_off += chunk_size
        remaining -= chunk_size

    return res

def make_cab(layout, compress=True):

    nb_folder = len(layout)
    nb_files = sum([len(f) for f in layout])

    b = BinWriter()
    b.write('cccc', b'M', b'S', b'C', b'F') #sig
    b.write('<I', 0) #res1
    total_size_off = b.off
    b.write('<I', 0) #cbCabinet
    b.write('<I', 0) #res2
    first_file_off = b.off
    b.write('<I', 0) # coffFiles
    b.write('<I', 0) #res3
    b.write('<BBHH', 3, 1, nb_folder, nb_files)
    b.write('<H', 0) #flags
    b.write('<H', 42) #setID
    b.write('<H', 0) #icabinet

    folders = []

    # write all CFFOLDER
    for fol in layout:
        f = {}
        data = b''.join([data for fn,data in fol])
        f['cdata'] = make_cdatas(data, compress)
        f['coffCabStart_off'] = b.off
        b.write('<I', 0)
        b.write('<HH', len(f['cdata']), (1 if compress else 0))

        f['fsize'] = []
        f['foff'] = []
        f['name'] = []
        o = 0
        for fn,data in fol:
            print("MD5=%s"%md5(data))
            f['fsize'].append(len(data))
            f['foff'].append(o)
            f['name'].append(fn)
            o += len(data)

        folders.append(f)

    b.write_at(first_file_off, '<I', b.off)

    # write all CFFILE
    for i,fol in enumerate(folders):
        for j in range(len(fol['fsize'])):
            b.write('<I', fol['fsize'][j])
            b.write('<I', fol['foff'][j])
            b.write('<H', i) #ifolder
            b.write('<HHH', 0,0,0) #date,time,attrib
            b.append(fol['name'][j])
            b.write('B', 0)


    # write all CDATA
    for fol in folders:
        b.write_at(fol['coffCabStart_off'], '<I', b.off)
        for c in fol['cdata']:
            b.append(c)

    b.write_at(total_size_off, '<I', b.off)
    return b.buf


if __name__ == '__main__':
    main()
