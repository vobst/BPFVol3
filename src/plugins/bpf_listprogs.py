# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
A Volatility3 plugin that tries to display information
typically accessed via bpftool prog (list|dump) subcommands.
"""
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, ClassVar, Optional

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import RequirementInterface
from volatility3.framework.interfaces.context import (
    ContextInterface,
    ModuleInterface,
)
from volatility3.framework.interfaces.plugins import PluginInterface
from volatility3.utility.datastructures import XArray
from volatility3.utility.prog import BpfProg

if TYPE_CHECKING:
    from volatility3.framework.interfaces.objects import ObjectInterface


class ProgList(PluginInterface):
    """Lists the BPF programs present in a particular Linux memory image."""

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
            requirements.BooleanRequirement(
                name="raw",
                description="If set, the raw bytes are dumped instead of"
                "disassembling them.",
                optional=True,
                default=False,
            ),
        ]

    def _generator(
        self,
        filter_func: Callable[[BpfProg], bool] = lambda _: False,
        dump_jited: bool = False,
        dump_xlated: bool = False,
        raw: bool = False,
    ) -> Iterable[tuple[int, tuple]]:
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
                if raw:
                    with self.open(
                        f"prog_{hex(prog.prog.vol.get('offset'))}_"
                        f"{prog.aux.id}_mcode",
                    ) as f:
                        f.write(prog.mcode)
                else:
                    with self.open(
                        f"prog_{hex(prog.prog.vol.get('offset'))}_"
                        f"{prog.aux.id}_mdisasm",
                    ) as f:
                        f.write(prog.dump_mcode().encode("UTF-8"))
            if dump_xlated:
                if raw:
                    with self.open(
                        f"prog_{hex(prog.prog.vol.get('offset'))}_"
                        f"{prog.aux.id}_bcode",
                    ) as f:
                        f.write(prog.bcode())
                else:
                    with self.open(
                        f"prog_{hex(prog.prog.vol.get('offset'))}_"
                        f"{prog.aux.id}_bdisasm",
                    ) as f:
                        f.write(prog.dump_bcode().encode("UTF-8"))
            yield (0, prog.row())

    @classmethod
    def list_progs(
        cls,
        context: ContextInterface,
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
        vmlinux: ModuleInterface = context.modules[vmlinux_module_name]
        prog_idr: ObjectInterface = vmlinux.object_from_symbol(
            symbol_name="prog_idr"
        )

        xarray: XArray = XArray(prog_idr.idr_rt, "bpf_prog", context)

        for prog in xarray.xa_for_each():
            prog: BpfProg = BpfProg(prog, context)  # noqa: PLW2901
            if filter_func(prog):
                continue
            yield prog

    @classmethod
    def create_filter(
        cls,
        id_list: Optional[list[int]] = None,
    ) -> Callable[[BpfProg], bool]:
        """Constructs a filter function for BPF programs.
        Note:
            PID filtering is not implemented.
        Args:
            id_list: List of BPF program IDs that are acceptable
                (or None if all are acceptable)
        Returns:
            Function which, when provided a BPF program object, returns
            True iff the program is to be filtered out of the list
        """
        id_list = id_list or []
        id_filter_list: list[int] = [x for x in id_list if x is not None]
        if id_filter_list:

            def filter_func(x: BpfProg) -> bool:
                return int(x.aux.id) not in id_filter_list

            return filter_func

        return lambda _: False

    def run(self) -> renderers.TreeGrid:
        columns: list[tuple[str, type]] = [
            ("OFFSET (V)", str),
            ("ID", int),
            ("TYPE", str),
            ("NAME", str),
            ("TAG", str),
            ("LOADED AT", int),
            ("MAP IDs", str),
            ("BTF ID", int),
            ("HELPERS", str),
        ]

        filter_func: Callable[[BpfProg], bool] = self.create_filter(
            self.config.get("id", None)
        )
        dump_jited: bool = bool(self.config.get("dump_jited"))
        dump_xlated: bool = bool(self.config.get("dump_xlated"))
        raw: bool = bool(self.config.get("raw"))

        return renderers.TreeGrid(
            columns,
            self._generator(filter_func, dump_jited, dump_xlated, raw),
        )
