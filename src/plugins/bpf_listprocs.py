# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""A Volatility3 plugin that lists processes that hold BPF objects via fd."""
import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, ClassVar

from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import RequirementInterface
from volatility3.framework.interfaces.context import (
    ContextInterface,
    ModuleInterface,
)
from volatility3.framework.interfaces.plugins import PluginInterface
from volatility3.framework.objects import utility
from volatility3.framework.renderers import TreeGrid
from volatility3.framework.symbols.linux.extensions import task_struct
from volatility3.plugins.linux.lsof import Lsof
from volatility3.utility.link import BpfLink
from volatility3.utility.map import BpfMap
from volatility3.utility.prog import BpfProg

if TYPE_CHECKING:
    from volatility3.framework.interfaces.objects import ObjectInterface


vollog: logging.Logger = logging.getLogger(__name__)


class BpfPslist(PluginInterface):
    """Lists processes that hold BPF objects via fd."""

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
            requirements.PluginRequirement(
                name="lsof",
                plugin=Lsof,
                version=(1, 1, 0),
            ),
        ]

    @classmethod
    def list_bpf_procs(
        cls,
        context: ContextInterface,
        symbol_table: str,
    ) -> Iterable[
        tuple[task_struct, list[BpfProg], list[BpfMap], list[BpfLink]]
    ]:
        vmlinux: ModuleInterface = context.modules[symbol_table]

        # bpf maps and progs were introduced in 99c55f7, v3.18-rc1
        bpf_prog_fops: int = (
            vmlinux.get_absolute_symbol_address("bpf_prog_fops")
            if vmlinux.has_symbol("bpf_prog_fops")
            else -1
        )
        bpf_map_fops: int = (
            vmlinux.get_absolute_symbol_address("bpf_map_fops")
            if vmlinux.has_symbol("bpf_map_fops")
            else -1
        )
        # bpf links were introduced in 70ed506, v5.7-rc1
        bpf_link_fops: int = (
            vmlinux.get_absolute_symbol_address("bpf_link_fops")
            if vmlinux.has_symbol("bpf_link_fops")
            else -1
        )
        vollog.debug(
            f"file_operations at: prog {hex(bpf_prog_fops)}, map {hex(bpf_map_fops)}, link {hex(bpf_link_fops)}"
        )

        progs: list[BpfProg] = []
        maps: list[BpfMap] = []
        links: list[BpfLink] = []
        fds_generator: Iterable[
            tuple[int, Any, task_struct, Any]
        ] = Lsof.list_fds(context, symbol_table)
        saved_pid: int | None = None
        saved_task: task_struct | None = None
        for pid, comm, _task, fd_fields in fds_generator:
            # first iteration
            if saved_task is None or saved_pid is None:
                saved_pid = int(pid)
                saved_task = _task

            # next task
            if pid != saved_pid:
                if progs or maps or links:
                    yield saved_task, progs, maps, links
                saved_pid = int(pid)
                saved_task = _task
                progs.clear()
                maps.clear()
                links.clear()

            # add if BPF object
            filp: ObjectInterface = fd_fields[1]
            vollog.debug(
                f"Checking: pid {pid}, comm {comm}, fd {fd_fields[0]}, op {hex(int(filp.f_op))} {vmlinux.get_symbols_by_absolute_location(int(filp.f_op))}"
            )
            if int(filp.f_op) == bpf_prog_fops:
                progs.append(BpfProg(int(filp.private_data), context))
            elif int(filp.f_op) == bpf_map_fops:
                maps.append(BpfMap(int(filp.private_data), context))
            elif int(filp.f_op) == bpf_link_fops:
                links.append(BpfLink(int(filp.private_data), context))
            else:
                continue

        # the last task holds BPF objects
        if progs or maps or links:
            assert saved_task is not None
            yield saved_task, progs, maps, links

    def _generator(
        self,
    ) -> Iterable[tuple[int, tuple]]:
        symbol_table: str = str(self.config["kernel"])

        for task, progs, maps, links in self.list_bpf_procs(
            self.context, symbol_table
        ):
            yield (
                0,
                (
                    int(task.pid),
                    utility.array_to_string(task.comm),
                    ",".join([str(prog.aux.id) for prog in progs]),
                    ",".join([str(map_.map.id) for map_ in maps]),
                    ",".join([str(link.link.id) for link in links]),
                ),
            )

    def run(self) -> TreeGrid:
        columns: list[tuple[str, type]] = [
            ("PID", int),
            ("COMM", str),
            ("PROGS", str),
            ("MAPS", str),
            ("LINKS", str),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )
