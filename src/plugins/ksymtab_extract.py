import logging
import string
import itertools
from typing import List, Iterable

from volatility3.framework import (
    interfaces,
    renderers,
    layers,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


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
                f.write("0x{:x} - {}\n".format(*e))

    def dump_raw(self, filename):
        with open(filename, "wb") as f:
            f.write(self.raw_data)

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


class Ksymtab:
    def __init__(self):
        self.table = []
        self.offset = 0


class KsymtabExtract(interfaces.plugins.PluginInterface):
    """Extracts the kernel symbol table from the dump."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 0, 0)

    @classmethod
    def get_requirements(
        cls,
    ) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer to scan",
            ),
        ]

    @classmethod
    def _search_string_tables_fast(
        cls,
        context: interfaces.context.ContextInterface,
        layer: interfaces.layers.TranslationLayerInterface,
    ) -> Iterable[StringTable]:

        printable_chars = set(bytes(string.printable, "ASCII"))

        def isprintable(_bytes: bytes):
            nonlocal printable_chars
            return all(b in printable_chars for b in _bytes)

        def find_strtab_boundary(
            layer: interfaces.layers.TranslationLayerInterface,
            offset: int,
            direction: int,
        ) -> int:
            """Given an offset that is within a string table, returns
            the boundary of the string table in a given direction"""
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

        # heuristic: pick some string where we are pretty certain that
        #   it exists within the kernel string table
        for offset in layer.scan(
            context=context,
            scanner=scanners.BytesScanner(b"unregister_kprobe\x00"),
        ):
            start = find_strtab_boundary(layer, offset, -1)
            end = find_strtab_boundary(layer, offset, 1) + 1
            yield StringTable(layer.read(start, end - start)+b'\x00', start)

    @classmethod
    def _probably_kernel_strtab(cls, strtab: StringTable) -> bool:
        return True

    @classmethod
    def ksymtab_extract(
        cls,
        context: interfaces.context.ContextInterface,
        virt_layer: interfaces.layers.TranslationLayerInterface,
        phys_layer: interfaces.layers.TranslationLayerInterface,
    ) -> Iterable[Ksymtab]:
        """Extracts the kernel symbol table from the dump."""
        vollog.info(f"{phys_layer.metadata.architecture=}")
        for strtab in cls._search_string_tables_fast(
            context, phys_layer
        ):
            if not cls._probably_kernel_strtab(strtab):
                continue
            strtab.dump_raw(f"{hex(strtab.offset)}_strtab.sec")
            print(strtab.table)

            yield Ksymtab()

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if isinstance(layer, layers.intel.Intel):
            virt_layer = layer
            phys_layer = self.context.layers[layer.config["memory_layer"]]
        else:
            virt_layer = None
            phys_layer = layer
        for ksymtab in self.ksymtab_extract(
            self.context, virt_layer, phys_layer
        ):
            yield 0, (
                format_hints.Hex(ksymtab.offset),
                len(ksymtab.table),
            )

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Nr. Symbols", int)],
            self._generator(),
        )
