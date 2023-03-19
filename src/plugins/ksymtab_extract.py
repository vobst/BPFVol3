"""
This plugin attempts to extract the kernel symbol table
__ksymtab from a Linux memory dump. On it's own, this is not providing
sufficient information to power Vol3 analyses. (On my machine, it
provides ~12500 symbols,
try cat /proc/kallsyms | rg ' __ksymtab_[^\s]+$' | wc.)
"""

import logging
from typing import List, Iterable, Optional

from volatility3.framework import (
    interfaces,
    renderers,
    layers,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints

from volatility3.utility.ksymtab import (
    StringTable,
    find_strtab_boundary,
    Ksymtab,
    find_symtab_boundary,
    PosRefScanner,
)

vollog = logging.getLogger(__name__)


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
    def _search_string_tables(
        cls,
        context: interfaces.context.ContextInterface,
        layer: interfaces.layers.TranslationLayerInterface,
    ) -> Iterable[StringTable]:
        """Extracts string tables from the dump"""
        # heuristic: pick some string where we are pretty certain that
        #   it is in the kernel string table across as many
        #   versions and configurations as possible; old GPL core kernel
        #   functions might be good
        for offset in layer.scan(
            context=context,
            scanner=scanners.BytesScanner(b"pipe_lock\x00"),
        ):
            start = find_strtab_boundary(layer, offset, -1)
            end = find_strtab_boundary(layer, offset, 1) + 1
            strtab = StringTable(
                layer.read(start, end - start) + b"\x00", start
            )
            if strtab.is_probably_kernel():
                yield strtab
            else:
                vollog.info(f"Rejecting strtab at {offset} since it"
                            " pobably is not kernel")

    @classmethod
    def _search_symbol_tables(
        cls,
        context: interfaces.context.ContextInterface,
        layer: interfaces.layers.TranslationLayerInterface,
        strtab: StringTable
    ) -> Iterable[Ksymtab]:
        """Searches for the kernel symbol table that belongs to the
        string table."""
        for offset in layer.scan(
            context=context,
            scanner=PosRefScanner(strtab.lookup_name("pipe_lock")[0]),
        ):
            start = find_symtab_boundary(layer, offset, -1, strtab)
            end = find_symtab_boundary(layer, offset, 1, strtab) + 1
            symtab = Ksymtab(
                layer.read(start, end - start), start
            )
            yield symtab

    @classmethod
    def ksymtab_extract(
        cls,
        context: interfaces.context.ContextInterface,
        virt_layer: Optional[
            interfaces.layers.TranslationLayerInterface
        ],
        phys_layer: interfaces.layers.TranslationLayerInterface,
    ) -> Iterable[Ksymtab]:
        """Extracts the kernel symbol table from the dump. There should
        only be one."""
        for strtab in cls._search_string_tables(context, phys_layer):
            strtab.dbg()
            for symtab in cls._search_symbol_tables(
                context, phys_layer, strtab
            ):
                yield symtab

    def _generator(self):
        # For better performance, make sure that we always scan the
        # physical memory.
        layer = self.context.layers[self.config["primary"]]
        if isinstance(layer, layers.intel.Intel):
            virt_layer = layer
            phys_layer = self.context.layers[
                layer.config["memory_layer"]
            ]
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
