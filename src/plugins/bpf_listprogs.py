"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT
"""

"""A Volatility3 plugin that tries to display information
typically accessed via bpftool prog (list|dump) subcommands"""
from typing import Iterable, Callable, Tuple, List, Any, Optional
from datetime import datetime

from volatility3.framework import interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements

from volatility3.utility.common import *


class ProgList(interfaces.plugins.PluginInterface):
    """Lists the BPF programs present in a particular Linux memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (0, 0, 0)

    columns = [
        ("OFFSET (V)", str),
        ("ID", int),
        ("NAME", str),
        ("TYPE", str),
        ("LOADED AT", datetime),
        ("HELPERS", str),
        ("MAPS", str),
        ("LINK TYPE", str),
        ("ATTACH TYPE", str),
        ("ATTACH TO", str),
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
                description="Filter on specific BPF prog IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump_jited",
                description="If set, the disassembled program"
                " is written to a text file.",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="dump_xlated",
                description="If set, the disassembled program"
                " bytecode is written to a text file.",
                optional=True,
                default=False,
            ),
        ]

    def _generator(
        self,
        filter_func: Callable[[BpfProg], bool] = lambda _: False,
        dump_jited: bool = False,
        dump_xlated: bool = False,
    ) -> Iterable[Tuple[int, Tuple]]:
        """Generates the BPF program list.
        Args:
            filter_func: A function which takes a BPF program object and
                returns True if the program should be ignored/filtered.
            dump: If True, native program instructions and
                bytecode are written to a file.
        Yields:
            Each row
        """
        for prog in self.list_progs(
            self.context, self.config["kernel"], filter_func
        ):
            if dump_jited:
                with self.open(
                    f"{hex(prog.prog.vol.get('offset'))}_prog_"
                    f"{prog.aux.id}_mdisasm",
                ) as f:
                    f.write(prog.dump_mcode().encode("UTF-8"))
            if dump_xlated:
                with self.open(
                    f"{hex(prog.prog.vol.get('offset'))}_prog_"
                    f"{prog.aux.id}_bdisasm",
                ) as f:
                    f.write(prog.dump_bcode().encode("UTF-8"))
            yield (0, prog.row())

    @classmethod
    def list_progs(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str = "kernel",
        filter_func: Callable[[BpfProg], bool] = lambda _: False,
    ) -> Iterable[BpfProg]:
        """Lists all the BPF programs in the primary layer.
        Args:
            context: The context to retrieve required elements
                (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which
                to operate
            filter_func: A function which takes a BPF program object and
                returns True if the program should be ignored/filtered
        Yields:
            BPF program objects
        """
        vmlinux = context.modules[vmlinux_module_name]
        prog_idr = vmlinux.object_from_symbol(symbol_name="prog_idr")

        xarray = XArray(prog_idr.idr_rt, "bpf_prog", context)

        for prog in xarray.xa_for_each():
            prog = BpfProg(prog, context)
            if filter_func(prog):
                continue
            yield prog

    @classmethod
    def create_filter(
        cls,
        pid_list: Optional[List[int]] = None,
        id_list: Optional[List[int]] = None,
    ) -> Callable[[Any], bool]:
        """Constructs a filter function for BPF programs.
        Note:
            PID filtering is not implemented.
        Args:
            pid_list: List of process IDs that are acceptable
                (or None if all are acceptable)
            pid_list: List of BPF program IDs that are acceptable
                (or None if all are acceptable)
        Returns:
            Function which, when provided a BPF program object, returns
            True iff the program is to be filtered out of the list
        """
        id_list = id_list or []
        id_filter_list = [x for x in id_list if x is not None]
        if id_filter_list:

            def filter_func(x):
                return int(x.aux.id) not in id_filter_list

            return filter_func
        else:
            return lambda _: False

    def run(self):
        filter_func = self.create_filter(
            self.config.get("pid", None), self.config.get("id", None)
        )
        dump_jited = self.config.get("dump_jited")
        dump_xlated = self.config.get("dump_xlated")

        return renderers.TreeGrid(
            self.columns,
            self._generator(filter_func, dump_jited, dump_xlated),
        )
