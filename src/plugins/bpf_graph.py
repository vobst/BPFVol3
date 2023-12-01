# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""A Volatility3 plugin that tries to visualize the state of the BPF
subsystem as a graph."""
from collections.abc import Iterable
from enum import Enum
from typing import ClassVar

import networkx as nx

from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import RequirementInterface
from volatility3.framework.interfaces.plugins import PluginInterface
from volatility3.framework.objects import utility
from volatility3.framework.renderers import TreeGrid
from volatility3.plugins.linux.bpf_listlinks import LinkList
from volatility3.plugins.linux.bpf_listmaps import MapList
from volatility3.plugins.linux.bpf_listprocs import BpfPslist
from volatility3.plugins.linux.bpf_listprogs import ProgList
from volatility3.utility.prog import BpfProg


class NodeType(Enum):
    MAP = 1
    PROG = 2
    LINK = 3
    PROCESS = 4


class EdgeType(Enum):
    MAP = 1
    FD = 2
    LINK = 3


node_map_dict: dict[str, NodeType | str] = {
    "node_type": NodeType.MAP,
    "shape": "oval",
    "style": "filled",
}

node_prog_dict: dict[str, NodeType | str] = {
    "node_type": NodeType.PROG,
    "shape": "note",
    "style": "filled",
}

node_link_dict: dict[str, NodeType | str] = {
    "node_type": NodeType.LINK,
    "shape": "hexagon",
    "style": "filled",
}

node_proc_dict: dict[str, NodeType | str] = {
    "node_type": NodeType.PROCESS,
    "shape": "diamond",
    "style": "filled",
}

edge_map_dict: dict[str, EdgeType | str] = {
    "edge_type": EdgeType.MAP,
}

edge_link_dict: dict[str, EdgeType | str] = {
    "edge_type": EdgeType.LINK,
    "style": "dashed",
}

edge_fd_dict: dict[str, EdgeType | str] = {
    "edge_type": EdgeType.FD,
    "style": "dotted",
}


class BpfGraph(PluginInterface):
    """Plots the state of the BPF subsystem as a graph."""

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
                name="bpf_listlinks",
                plugin=LinkList,
                version=(0, 0, 0),
            ),
            requirements.PluginRequirement(
                name="bpf_proc",
                plugin=BpfPslist,
                version=(0, 0, 0),
            ),
        ]

    @classmethod
    def _get_color(cls, hashable) -> str:
        return "#" + hex(hash(hashable))[-6:].upper()

    def _generate_graph(self) -> list[str]:
        g = nx.Graph()

        # add all the maps, color nodes according to the map type
        g.add_nodes_from(
            [
                (
                    m.label,
                    node_map_dict
                    | {
                        "bpf_id": int(m.map.id),
                        "name": m.name,
                        "label": m.label,
                        "fillcolor": self._get_color(m.type),
                    },
                )
                for m in MapList.list_maps(self.context, self.config["kernel"])
            ]
        )

        # add all the programs and connect them to their maps, color
        # nodes according to program type
        for prog in ProgList.list_progs(self.context, self.config["kernel"]):
            g.add_nodes_from(
                [
                    (
                        prog.label,
                        node_prog_dict
                        | {
                            "bpf_id": int(prog.aux.id),
                            "name": prog.name,
                            "label": prog.label,
                            "fillcolor": self._get_color(prog.type),
                        },
                    )
                ]
            )
            g.add_edges_from(
                [
                    (
                        prog.label,
                        m.label,
                        edge_map_dict,
                    )
                    for m in prog.maps
                ]
            )

        # add all links and connect them to their programs, color according to
        # link type
        for lnk in LinkList.list_links(self.context, self.config["kernel"]):
            g.add_nodes_from(
                [
                    (
                        lnk.label,
                        node_link_dict
                        | {
                            "bpf_id": int(lnk.link.id),
                            "label": lnk.label,
                            "fillcolor": self._get_color(lnk.type),
                        },
                    )
                ]
            )
            g.add_edges_from(
                [
                    (
                        BpfProg(lnk.prog, self.context).label,
                        lnk.label,
                        edge_link_dict,
                    )
                ]
            )

        # add all processes that hold BPF objects via fd, connect them
        # to their resources, color according to pid
        for task_, progs, maps, links in BpfPslist.list_bpf_procs(
            self.context, self.config["kernel"]
        ):
            task_comm: str = str(utility.array_to_string(task_.comm))
            task_label: str = f"{int(task_.pid)}/{task_comm}"
            g.add_nodes_from(
                [
                    (
                        task_label,
                        node_proc_dict
                        | {
                            "pid": int(task_.pid),
                            "comm": task_comm,
                            "label": f"{int(task_.pid)}/{task_comm}",
                            "fillcolor": self._get_color(str(task_.pid)),
                        },
                    )
                ]
            )
            g.add_edges_from(
                [
                    (
                        task_label,
                        m.label,
                        edge_fd_dict,
                    )
                    for m in maps
                ]
                + [
                    (
                        task_label,
                        prog.label,
                        edge_fd_dict,
                    )
                    for prog in progs
                ]
                + [
                    (
                        task_label,
                        link.label,
                        edge_fd_dict,
                    )
                    for link in links
                ]
            )

        ag = nx.nx_agraph.to_agraph(g)
        ag.graph_attr["overlap"] = "false"

        files: list[str] = []
        filename: str = "graph"

        with self.open(f"{filename}.dot") as f:
            files.append(str(f.preferred_filename))
            ag.write(f)

        ag.draw(f"{filename}.png", format="png", prog="neato")
        files.append(f"{filename}.png")

        return files

    def _generator(
        self,
    ) -> Iterable[tuple[int, tuple]]:
        for filename in self._generate_graph():
            yield (0, ("OK", filename))

    def run(self) -> TreeGrid:
        columns: list[tuple[str, type]] = [
            ("STATUS", str),
            ("FILE", str),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )
