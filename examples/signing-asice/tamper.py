#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Copy an ASiC-E container, flipping one bit of one byte of a data object.

Usage: tamper.py IN.asice OUT.asice ENTRY    (ENTRY = name of the signed document inside the zip)
Everything else (entry order, compression, signature) is copied unchanged.
"""
import sys
import zipfile

src, dst, entry = sys.argv[1:4]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, "w") as zo:
    for info in zi.infolist():
        data = zi.read(info.filename)
        if info.filename == entry:
            data = bytes([data[0] ^ 0x01]) + data[1:]
            print("tampered %s: first byte %#04x -> %#04x" % (entry, data[0] ^ 0x01, data[0]))
        zo.writestr(info, data, compress_type=info.compress_type)
