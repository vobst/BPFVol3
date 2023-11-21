"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT
"""

"""A Volatility3 plugin that lists processes that hold BPF objects
via fd."""
from typing import Iterable, Tuple, List

from volatility3.framework import interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

from volatility3.plugins.linux.bpf_listmaps import MapList
from volatility3.plugins.linux.bpf_listprogs import ProgList
from volatility3.plugins.linux.lsof import Lsof

from volatility3.utility.prog import BpfProg, BpfLink
from volatility3.utility.map import BpfMap


class BpfPslist(interfaces.plugins.PluginInterface):
    """Lists processes that hold BPF objects via fd."""

    _required_framework_version = (2, 0, 0)

    _version = (0, 0, 0)

    columns = [
        ("PID", int),
        ("COMM", str),
        ("PROGS", str),
        ("MAPS", str),
        ("LINKS", str),
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
            requirements.PluginRequirement(
                name="bpf_listmaps",
                plugin=MapList,
                version=(0, 0, 0),
            ),
            requirements.PluginRequirement(
                name="bpf_listprogs",
                plugin=ProgList,
                version=(0, 0, 0),
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
        context: interfaces.context.ContextInterface,
        symbol_table: str,
    ):
        vmlinux = context.modules[symbol_table]
        # bpf maps and progs were introduced in 99c55f7, v3.18-rc1
        bpf_prog_fops = (
            vmlinux.get_absolute_symbol_address("bpf_prog_fops")
            if vmlinux.has_symbol("bpf_prog_fops")
            else -1
        )
        bpf_map_fops = (
            vmlinux.get_absolute_symbol_address("bpf_map_fops")
            if vmlinux.has_symbol("bpf_map_fops")
            else -1
        )
        # bpf links were introduced in 70ed506, v5.7-rc1
        bpf_link_fops = (
            vmlinux.get_absolute_symbol_address("bpf_link_fops")
            if vmlinux.has_symbol("bpf_link_fops")
            else -1
        )

        progs = []
        maps = []
        links = []
        fds_generator = Lsof.list_fds(context, symbol_table)
        for pid, comm, _task, fd_fields in fds_generator:
            if pid == 1:
                prev_pid = 1
                prev_task = _task

            if pid != prev_pid and (progs or maps or links):
                yield prev_task, progs, maps, links
                prev_pid = pid
                prev_task = _task
                progs.clear()
                maps.clear()
                links.clear()

            filp = fd_fields[1]
            if int(filp.f_op) == bpf_prog_fops:
                progs.append(BpfProg(filp.private_data, context))
            elif int(filp.f_op) == bpf_map_fops:
                maps.append(BpfMap(filp.private_data, context))
            elif int(filp.f_op) == bpf_link_fops:
                links.append(BpfLink(filp.private_data, context))
            else:
                continue

        if progs or maps or links:
            yield prev_task, progs, maps, links

    def _generator(
        self,
    ) -> Iterable[Tuple[int, Tuple]]:
        symbol_table = self.config["kernel"]

        for task, progs, maps, links in self.list_bpf_procs(
            self.context, symbol_table
        ):
            yield (
                0,
                tuple(
                    (
                        int(task.pid),
                        utility.array_to_string(task.comm),
                        ",".join([str(prog.aux.id) for prog in progs]),
                        ",".join([str(_map.map.id) for _map in maps]),
                        ",".join([str(link.link.id) for link in links]),
                    )
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            self.columns,
            self._generator(),
        )
