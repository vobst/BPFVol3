# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""A Volatility3 plugin that tries to visualize the state of the BPF
subsystem as a graph."""
import colorsys
import logging
from collections.abc import Callable, Iterable
from enum import Enum
from hashlib import sha256
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

vollog: logging.Logger = logging.getLogger(__name__)


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


def _convert_to_node_type(cli_type: str) -> NodeType | None:
    node_type: NodeType | None = None
    match cli_type:
        case "prog":
            node_type = NodeType.PROG
        case "map":
            node_type = NodeType.MAP
        case "link":
            node_type = NodeType.LINK
        case "proc":
            node_type = NodeType.PROCESS
        case _:
            vollog.error(f"Invalid node type: {cli_type}")

    return node_type


def _gen_node_type_include(
    cli_types: list[str] | None,
) -> Callable[[NodeType], bool]:
    if not cli_types:
        return lambda *_: True

    node_types: list[NodeType | None] = [
        _convert_to_node_type(cli_type) for cli_type in cli_types
    ]

    return lambda node_type: node_type in [
        nt for nt in node_types if nt is not None
    ]


def _gen_node_filter(cli_nodes: list[str]) -> Callable[[NodeType, int], bool]:
    cli_nodes_split: list[list[str]] = [
        cli_node.split("-") for cli_node in cli_nodes
    ]
    nodes: list[tuple[NodeType, int]] = []

    for cli_node_split in cli_nodes_split:
        if len(cli_node_split) != 2:  # noqa: PLR2004
            vollog.error(f"Invalid node argument: {cli_node_split}")
            return lambda *_: False

        node_type: NodeType | None = _convert_to_node_type(cli_node_split[0])
        if node_type is None:
            vollog.error(f"Invalid node type: {cli_node_split[0]}")
            return lambda *_: False

        try:
            obj_id: int = int(cli_node_split[1])
        except ValueError:
            vollog.error(f"Invalid node object ID: {cli_node_split[1]}")
            return lambda *_: False

        nodes.append((node_type, obj_id))

    return lambda node_type, obj_id: (node_type, obj_id) not in nodes


def _restict_to_components(
    g: nx.Graph, component_node_filter: Callable[[NodeType, int], bool]
) -> nx.Graph:
    components: list[nx.Graph] = []
    nodes: set[str] = set()
    node_types: dict[str, NodeType] = nx.get_node_attributes(g, "node_type")
    pids: dict[str, int] = nx.get_node_attributes(g, "pid")
    bpf_ids: dict[str, int] = nx.get_node_attributes(g, "bpf_id")

    for node in g:
        node_type: NodeType = node_types[node]

        obj_id: int = -1
        match node_type:
            case NodeType.PROCESS:
                obj_id = pids[node]
            case _:
                obj_id = bpf_ids[node]

        if component_node_filter(node_type, obj_id):
            continue

        nodes.add(node)

    for component in nx.connected_components(g):
        if not component.intersection(nodes):
            continue

        components.append(g.subgraph(component))

    return nx.compose_all(components)


def _get_color(stringable) -> str:
    value: int = (
        int.from_bytes(sha256(str(stringable).encode()).digest()[:4], "little")
        & 0xFFFFFFFF
    )
    hsv: tuple[float, float, float] = (value / 0xFFFFFFFF, 0.1, 1.0)
    rgb: tuple[float, float, float] = colorsys.hsv_to_rgb(*hsv)
    hex_string = "".join(f"{int(i * 255):X}" for i in rgb)

    return f"#{hex_string}"


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
            requirements.ListRequirement(
                name="components",
                description="Only generate the connected components containing the given nodes",
                element_type=str,
                optional=True,
            ),
            requirements.ListRequirement(
                name="types",
                description="Include nodes of the given types",
                element_type=str,
                optional=True,
            ),
        ]

    def _generate_graph(
        self,
        node_type_include: Callable[[NodeType], bool],
        component_node_filter: Callable[[NodeType, int], bool] | None,
    ) -> list[str]:
        g: nx.Graph = nx.Graph()

        # TODO: include full `row` information in the nodes

        if node_type_include(NodeType.MAP):
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
                            "fillcolor": _get_color(m.type),
                        },
                    )
                    for m in MapList.list_maps(
                        self.context, self.config["kernel"]
                    )
                ]
            )

        if node_type_include(NodeType.PROG):
            # add all the programs and connect them to their maps, color
            # nodes according to program type
            for prog in ProgList.list_progs(
                self.context, self.config["kernel"]
            ):
                g.add_nodes_from(
                    [
                        (
                            prog.label,
                            node_prog_dict
                            | {
                                "bpf_id": int(prog.aux.id),
                                "name": prog.name,
                                "label": prog.label,
                                "fillcolor": _get_color(prog.type),
                            },
                        )
                    ]
                )
                if node_type_include(NodeType.MAP):
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

        if node_type_include(NodeType.LINK):
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
                                "fillcolor": _get_color(lnk.type),
                            },
                        )
                    ]
                )
                if node_type_include(NodeType.MAP):
                    g.add_edges_from(
                        [
                            (
                                BpfProg(lnk.prog, self.context).label,
                                lnk.label,
                                edge_link_dict,
                            )
                        ]
                    )

        if node_type_include(NodeType.PROCESS):
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
                                "fillcolor": _get_color(str(task_.pid)),
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
                        if node_type_include(NodeType.MAP)
                    ]
                    + [
                        (
                            task_label,
                            prog.label,
                            edge_fd_dict,
                        )
                        for prog in progs
                        if node_type_include(NodeType.PROG)
                    ]
                    + [
                        (
                            task_label,
                            link.label,
                            edge_fd_dict,
                        )
                        for link in links
                        if node_type_include(NodeType.LINK)
                    ]
                )

        if component_node_filter is not None:
            g = _restict_to_components(g, component_node_filter)

        ag = nx.nx_agraph.to_agraph(g)
        ag.graph_attr["overlap"] = "false"

        files: list[str] = []
        filename: str = "graph"

        with self.open(f"{filename}.dot") as f:
            files.append(str(f.preferred_filename))
            ag.write(f)

        ag.draw(f"{filename}.png", format="png", prog="neato")
        files.append(f"{filename}.png")

        # TODO: generate a legend

        return files

    def _generator(
        self,
        node_type_include: Callable[[NodeType], bool],
        component_node_filter: Callable[[NodeType, int], bool] | None,
    ) -> Iterable[tuple[int, tuple]]:
        for filename in self._generate_graph(
            node_type_include, component_node_filter
        ):
            yield (0, ("OK", filename))

    def run(self) -> TreeGrid:
        columns: list[tuple[str, type]] = [
            ("STATUS", str),
            ("FILE", str),
        ]

        node_type_include: Callable[[NodeType], bool] = _gen_node_type_include(
            self.config.get("types")
        )

        component_node_filter: Callable[[NodeType, int], bool] | None = None
        cli_component_nodes: list[str] | None = self.config.get("components")
        if cli_component_nodes:
            component_node_filter = _gen_node_filter(cli_component_nodes)

        return TreeGrid(
            columns,
            self._generator(node_type_include, component_node_filter),
        )
