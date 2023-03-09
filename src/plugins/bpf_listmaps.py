"""A Volatility3 plugin that tries to display information
typically accessed via bpftool map (list|dump) subcommands"""
from typing import Iterable, Callable, Tuple, List, Any

from volatility3.framework import interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements

from volatility3.utility.common import *


class MapList(interfaces.plugins.PluginInterface):
    """Lists the BPF maps present in a particular Linux memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (0, 0, 0)

    columns = [
        ("OFFSET (V)", str),
        ("ID", int),
        ("NAME", str),
        ("TYPE", str),
        ("KEY SIZE", int),
        ("VALUE SIZE", int),
        ("MAX ENTRIES", int),
    ]

    @classmethod
    def get_requirements(
        cls,
    ) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.ListRequirement(
                name="id",
                description="Filter on specific BPF map IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="If True, full map contents are written to"
                "a file.",
                optional=True,
                default=False,
            ),
        ]

    def _generator(
        self,
        filter_func: Callable[[BpfMap], bool] = lambda _: False,
        dump: bool = False,
    ) -> Iterable[Tuple[int, Tuple]]:
        """Generates the BPF map list.
        Args:
            filter_func: A function which takes a BPF map object and
                returns True if the map should be ignored/filtered.
            dump: If True, full map contents are written to a file.
        Yields:
            Each row
        """
        for m in self.list_maps(
            self.context, self.config["kernel"], filter_func
        ):
            if dump:
                with self.open(f"{hex(m.map.vol.get('offset'))}_map_"
                    f"{m.map.id}") as f:
                    f.write(m.dump().encode("UTF-8"))

            yield (0, m.row())

    @classmethod
    def list_maps(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str = "kernel",
        filter_func: Callable[[BpfMap], bool] = lambda _: False,
    ) -> Iterable[BpfMap]:
        """Lists all the BPF maps in the primary layer.
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
        vmlinux = context.modules[vmlinux_module_name]
        map_idr = vmlinux.object_from_symbol(symbol_name="map_idr")

        xarray = XArray(map_idr.idr_rt, "bpf_map", context)

        for m in xarray.xa_for_each():
            m = BpfMap(m, context)
            if filter_func(m):
                continue
            yield m

    @classmethod
    def create_filter(
        cls, pid_list: List[int] = None, id_list: List[int] = None
    ) -> Callable[[Any], bool]:
        """Constructs a filter function for BPF maps.
        Note:
            PID filtering is not implemented.
        Args:
            pid_list: List of process IDs that are acceptable
                (or None if all are acceptable)
            pid_list: List of BPF map IDs that are acceptable
                (or None if all are acceptable)
        Returns:
            Function which, when provided a BPF map object, returns True
            iff the map is to be filtered out of the list
        """
        id_list = id_list or []
        id_filter_list = [x for x in id_list if x is not None]
        if id_filter_list:

            def filter_func(x):
                return int(x.map.id) not in id_filter_list

            return filter_func
        else:
            return lambda _: False

    def run(self):
        filter_func = self.create_filter(
            self.config.get("pid", None), self.config.get("id", None)
        )
        dump = self.config.get("dump")

        return renderers.TreeGrid(
            self.columns,
            self._generator(filter_func, dump),
        )
