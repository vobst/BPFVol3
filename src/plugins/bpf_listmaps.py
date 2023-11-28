# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
A Volatility3 plugin that tries to display information
typically accessed via bpftool map (list|dump) subcommands
"""
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any, ClassVar, Optional

from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import RequirementInterface
from volatility3.framework.interfaces.context import (
    ContextInterface,
    ModuleInterface,
)
from volatility3.framework.interfaces.plugins import PluginInterface
from volatility3.framework.renderers import TreeGrid
from volatility3.utility.datastructures import XArray
from volatility3.utility.map import BpfMap

if TYPE_CHECKING:
    from volatility3.framework.interfaces.objects import ObjectInterface


class MapList(PluginInterface):
    """Lists the BPF maps present in a particular Linux memory image."""

    _required_framework_version: ClassVar = (2, 0, 0)

    _version: ClassVar = (0, 0, 0)

    @classmethod
    def get_requirements(
        cls,
    ) -> list[RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="id",
                description="Filter on specific BPF map IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="If True, map contents are written to a file.",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="raw",
                description="If True, raw map contents are written to a file.",
                optional=True,
                default=False,
            ),
        ]

    def _generator(
        self,
        filter_func: Callable[[BpfMap], bool] = lambda _: False,
        dump: bool = False,
    ) -> Iterable[tuple[int, tuple]]:
        """Generates the BPF map list
        Args:
            filter_func: A function which takes a BPF map object and
                returns True if the map should be ignored/filtered
            dump: If True, full map contents are written to a file
        Yields:
            Each row
        """
        for m in self.list_maps(
            self.context, self.config["kernel"], filter_func
        ):
            if dump:
                with self.open(
                    f"map_{hex(m.map.vol.get('offset'))}_{m.map.id}"
                ) as f:
                    f.write(m.dump().encode("UTF-8"))

            yield (0, m.row())

    @classmethod
    def list_maps(
        cls,
        context: ContextInterface,
        vmlinux_module_name: str = "kernel",
        filter_func: Callable[[BpfMap], bool] = lambda _: False,
    ) -> Iterable[BpfMap]:
        """Lists all the BPF maps in the primary layer
        Args:
            context: The context to retrieve required elements
                (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which
                to operate
            filter_func: A function which takes a BPF map object and
                returns True if the map should be ignored/filtered
        Yields:
            BPF map objects
        """
        vmlinux: ModuleInterface = context.modules[vmlinux_module_name]
        map_idr: ObjectInterface = vmlinux.object_from_symbol(
            symbol_name="map_idr"
        )

        xarray: XArray = XArray(map_idr.idr_rt, "bpf_map", context)

        for m in xarray.xa_for_each():
            m: BpfMap = BpfMap(m, context)  # noqa: PLW2901
            if filter_func(m):
                continue
            yield m

    @classmethod
    def create_filter(
        cls,
        id_list: Optional[list[int]] = None,
    ) -> Callable[[BpfMap], bool]:
        """Constructs a filter function for BPF maps
        Args:
            id_list: List of BPF map IDs that are acceptable
                (or None if all are acceptable)
        Returns:
            Function which, when provided a BPF map object, returns True
            iff the map is to be filtered out of the list
        """
        id_list = id_list or []
        id_filter_list: list[int] = [x for x in id_list if x is not None]
        if id_filter_list:

            def filter_func(x: BpfMap) -> bool:
                return int(x.map.id) not in id_filter_list

            return filter_func

        return lambda _: False

    def run(self) -> TreeGrid:
        columns: list[tuple[str, Any]] = [
            ("OFFSET (V)", str),
            ("ID", int),
            ("TYPE", str),
            ("NAME", str),
            ("KEY SIZE", int),
            ("VALUE SIZE", int),
            ("MAX ENTRIES", int),
        ]

        filter_func: Callable[[BpfMap], bool] = self.create_filter(
            self.config.get("id", None)
        )
        dump: bool = bool(self.config.get("dump"))

        return TreeGrid(
            columns,
            self._generator(filter_func, dump),
        )
