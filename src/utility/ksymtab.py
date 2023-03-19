"""
This file contains classes and functions to support the extraction
of the kernel symbol table.
"""

import logging
import itertools
import string
from hashlib import md5
from volatility3.framework import interfaces

vollog = logging.getLogger(__name__)


def isprintable(_bytes: bytes):
    printable_chars = set(bytes(string.printable, "ASCII"))
    return all(b in printable_chars for b in _bytes)


def find_strtab_boundary(
    layer: interfaces.layers.TranslationLayerInterface,
    offset: int,
    direction: int,
) -> int:
    """Given an offset that is within a string table, returns
    the last byte that is inside the string table in a given direction.
    """
    i = 0
    null_count = 0
    while True:
        b = layer.read(offset + direction * i, 1)
        if isprintable(b):
            null_count = 0
            i += 1
            continue
        elif b == b"\x00":
            null_count += 1
            # heuristic: three consecutive null bytes shall not
            #   appear within a string table
            if null_count > 2:
                i -= 3
                break
            i += 1
            continue
        else:
            # only printable and null bytes shall appear in a
            # string table
            i -= 1 + null_count
            break
    return offset + direction * i


class StringTable:
    def __init__(self, raw_data: bytes, offset: int = 0):
        self.table = list(self.parse_raw(raw_data, offset))
        self.offset = offset
        self.raw_data = raw_data

    def lookup_addr(self, addr: int):
        res = None
        if addr - self.offset > 0:
            res = (
                addr,
                bytes(
                    itertools.takewhile(
                        lambda x: x != 0,
                        self.raw_data[addr - self.offset :],
                    )
                ).decode("ASCII"),
            )
            if not res[1]:
                res = None
        return res

    def lookup_name(self, name):
        return next((x for x in self.table if x[1] == name), None)

    def rebase(self, offset: int):
        old_offset = self.offset
        self.offset = offset
        self.table = [
            (x[0] - old_offset + offset, x[1]) for x in self.table
        ]

    def items(self):
        return self.table

    def __setitem__(self, key, value):
        self.table[key] = value

    def __getitem__(self, key):
        return self.table[key]

    def dump(self, filename):
        with open(filename, "w") as f:
            for e in self.table:
                f.write(f"{hex(e[0])} - {e[1]}\n")

    def dbg(self):
        for e in self.table:
            vollog.debug(f"{hex(e[0])} - {e[1]}")
        m = md5()
        m.update(self.raw_data)
        vollog.debug(
            f"Summary: offset={self.offset} size={len(self.raw_data)}"
            f" entries={len(self.table)} md5={m.digest()}"
        )

    def dump_raw(self, filename):
        with open(filename, "wb") as f:
            f.write(self.raw_data)

    def is_probably_kernel(self):
        strings = set({"input_event", "prepare_kernel_cred", "yield"})
        for _, name in self.table:
            if name in strings:
                print(name)
                strings.remove(name)
        return len(strings) == 0

    @staticmethod
    def parse_raw(raw_data: bytes, offset: int):
        p = 0
        while True:
            e = raw_data.find(b"\x00", p)
            if e == -1:
                break
            name = raw_data[p:e].decode("ASCII")
            if name:
                yield (p + offset, name)
            p = e + 1


def find_symtab_boundary(
    layer: interfaces.layers.TranslationLayerInterface,
    offset: int,
    direction: int,
    strtab: StringTable,
) -> int:
    """Given an offset that is within a symbol table that belongs to
    strtab, returns the last byte that is inside the symbol table in
    a given direction.
    """
    return 0


class Ksymtab:
    def __init__(self, raw_data: bytes, offset: int):
        self.table = []
        self.raw_data = raw_data
        self.offset = offset


class PosRefScanner(interfaces.layers.ScannerInterface):
    """Scans a layer for positional references to a particular offset
    'needle'."""

    def __init__(self, needle: int):
        super().__init__()
        self.needle = needle
