"""
This file contains classes and functions to support the extraction
of the kernel symbol table.
"""

import logging
import itertools
from collections import namedtuple
from struct import unpack
import string
from hashlib import md5
from volatility3.framework import interfaces
from typing import Generator

vollog = logging.getLogger(__name__)

from cffi import FFI

ffi = FFI()
ffi.cdef(
    """
    int64_t search_rel_pointer(const char* data, uint64_t len, uint64_t needle, uint64_t offset);
"""
)
lib = ffi.dlopen(
    "./volatility3/utility/cffi/search-ksymtab-rel-helper.so"
)


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
        ret = []
        for e in self.table:
            ret.append(f"{hex(e[0])} - {e[1]}")
        ret.append(self.info())
        return "\n".join(ret)

    def info(self) -> str:
        return (
            f"StringTable: offset={hex(self.offset)} "
            f"size={len(self.raw_data)} "
            f"entries={len(self.table)} md5={self.hash}"
        )

    @property
    def hash(self):
        m = md5()
        m.update(self.raw_data)
        return m.digest().hex()

    def dump_raw(self, filename):
        with open(filename, "wb") as f:
            f.write(self.raw_data)

    def is_probably_kernel(self):
        strings = set({"input_event", "prepare_kernel_cred", "yield"})
        for _, name in self.table:
            if name in strings:
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


SymtabEntry = namedtuple(
    "SymtabEntry", ["value_offset", "name_offset", "namespace_offset"]
)
setattr(SymtabEntry, "size", 12)


def find_symtab_boundary(
    layer: interfaces.layers.TranslationLayerInterface,
    offset: int,
    direction: int,
    strtab: StringTable,
) -> int:
    """Given an 'offset' that points to a symbol entry that lies within
    a symbol table that belongs to 'strtab', returns a pointer to the
    last entry that is inside the symbol table in a given 'direction'.
    """
    while True:
        entry = SymtabEntry(
            *unpack("<iii", layer.read(offset, SymtabEntry.size))
        )
        # check if the entry references a string within strtab
        if strtab.lookup_addr(entry.name_offset + offset + 4) == None:
            # revert the last step
            offset -= direction * SymtabEntry.size
            break
        vollog.debug(
            "Identified symbol table entry for "
            f"{strtab.lookup_addr(entry.name_offset + offset + 4)[1]}"
        )
        offset += direction * SymtabEntry.size

    return offset


class Ksymtab:
    def __init__(self, raw_data: bytes, offset: int):
        self.table = [
            SymtabEntry(
                *unpack("<iii", raw_data[i : i + SymtabEntry.size])
            )
            for i in range(0, len(raw_data), SymtabEntry.size)
        ]
        self.raw_data = raw_data
        self.offset = offset

    def info(self) -> str:
        return (
            f"SymbolTable: offset={hex(self.offset)} "
            f"size={len(self.raw_data)} "
            f"entries={len(self.table)} md5={self.hash}"
        )

    @property
    def hash(self):
        m = md5()
        m.update(self.raw_data)
        return m.digest().hex()

    def dump_raw(self, filename):
        with open(filename, "wb") as f:
            f.write(self.raw_data)

    def is_probably_kernel(self):
        return len(self.table) > 1000


class PosRefScanner(interfaces.layers.ScannerInterface):
    """Scans a layer for positional references to a particular offset
    'needle'."""

    thread_safe = True

    def __init__(self, needle: int):
        super().__init__()
        self.needle = needle

    def __call__(
        self, data: bytes, data_offset: int
    ) -> Generator[int, None, None]:
        """Runs through the 'data' looking for position relative
        references to the location 'needle', and yields all offsets
        where the references are found."""
        orig_offset = data_offset
        while True:
            # Our scan assumes that the chunks that Vol3 gives us are
            # 4 byte aligned. If this should ever be false, fail early.
            assert data_offset % 4 == 0
            cbuf = ffi.from_buffer(data)
            find_pos = lib.search_rel_pointer(
                cbuf, len(data), self.needle, data_offset
            )
            if find_pos < 0:
                break
            if find_pos + (data_offset - orig_offset) < self.chunk_size:
                yield find_pos + data_offset
            data = data[find_pos + 4 :]
            data_offset += find_pos + 4
