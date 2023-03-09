"""A Volatility3 plugin that tries to visualize the state of the BPF
subsystem as a graph."""
from typing import Iterable, Callable, Tuple, List, Any

from volatility3.framework import interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

from volatility3.plugins.linux.bpf_listmaps import MapList
from volatility3.plugins.linux.bpf_listprogs import ProgList
from volatility3.plugins.linux.bpf_proc import BpfPslist

import networkx as nx

from enum import Enum


class BpfGraph(interfaces.plugins.PluginInterface):
    """Plots the state of the BPF subsystem as a graph."""

    _required_framework_version = (2, 0, 0)

    columns = [
        ("STATUS", str),
        ("FILE", str),
    ]

    class NodeTypes(Enum):
        MAP = 1
        PROG = 2
        ATTACH_TYPE = 3
        PROCESS = 4

    class EdgeTypes(Enum):
        MAP = 1
        FD = 2
        ATTACH_TYPE = 3

    node_map_dict = {
        "node_type": NodeTypes.MAP,
        "shape": "oval",
    }

    node_prog_dict = {
        "node_type": NodeTypes.PROG,
        "shape": "note",
    }

    node_proc_dict = {
        "node_type": NodeTypes.PROCESS,
        "shape": "diamond",
        "fillcolor": "gray",
    }

    edge_map_dict = {
        "edge_type": EdgeTypes.MAP,
    }

    edge_fd_dict = {
        "edge_type": EdgeTypes.FD,
        "style": "dotted",
        "color": "gray",
    }

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
            requirements.StringRequirement(
                name="directory",
                description="Directory where output files are written",
                optional=False,
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
                name="bpf_proc",
                plugin=BpfPslist,
                version=(0, 0, 0),
            ),
        ]

    @classmethod
    def _get_color(cls, hashable) -> str:
        return "#" + hex(hash(hashable))[-6:].upper()

    def _generate_graph(self, directory: str) -> List[str]:
        G = nx.Graph()

        # add all the maps, color nodes according to the map type
        G.add_nodes_from(
            [
                (
                    f"{m.map.id}/{m.name}",
                    self.node_map_dict
                    | {
                        "id": int(m.map.id),
                        "name": m.name,
                        "fillcolor": self._get_color(m.type),
                    },
                )
                for m in MapList.list_maps(
                    self.context, self.config["kernel"]
                )
            ]
        )

        # add all the programs and connect them to their maps, color
        # nodes according to attach types
        for prog in ProgList.list_progs(
            self.context, self.config["kernel"]
        ):
            G.add_nodes_from(
                [
                    (
                        f"{prog.aux.id}/{prog.name}",
                        self.node_prog_dict
                        | {
                            "id": int(prog.aux.id),
                            "name": prog.name,
                            "label": prog.attach_to
                            + f"\n{prog.aux.id}/{prog.name}",
                            "fillcolor": self._get_color(
                                prog.type
                            ),
                        },
                    )
                ]
            )
            G.add_edges_from(
                [
                    (
                        f"{prog.aux.id}/{prog.name}",
                        f"{m.map.id}/{m.name}",
                        self.edge_map_dict,
                    )
                    for m in prog.maps
                ]
            )

        # add all processes that hold BPF objects via fd, connect them
        # to their resources, color according to pid
        for _task, progs, maps, _ in BpfPslist.list_bpf_procs(
            self.context, self.config["kernel"]
        ):
            task_comm = utility.array_to_string(_task.comm)
            G.add_nodes_from(
                [
                    (
                        f"{int(_task.pid)}/{task_comm}",
                        self.node_proc_dict
                        | {
                            "pid": int(_task.pid),
                            "comm": task_comm,
                            "label": f"{int(_task.pid)}/{task_comm}",
                        },
                    )
                ]
            )
            G.add_edges_from(
                [
                    (
                        f"{int(_task.pid)}/{task_comm}",
                        f"{m.map.id}/{m.name}",
                        self.edge_fd_dict,
                    )
                    for m in maps
                ]
            )
            G.add_edges_from(
                [
                    (
                        f"{int(_task.pid)}/{task_comm}",
                        f"{prog.aux.id}/{prog.name}",
                        self.edge_fd_dict,
                    )
                    for prog in progs
                ]
            )


        A = nx.nx_agraph.to_agraph(G)

        with open("/dumps/graph.dot", "w") as f:
            A.write(f)

        return ["file1", "file2"]

    def _generator(
        self,
        directory: str,
    ) -> Iterable[Tuple[int, Tuple]]:
        for filename in self._generate_graph(directory):
            yield (0, tuple(("OK", filename)))

    def run(self):
        directory = str(self.config.get("directory"))

        return renderers.TreeGrid(
            self.columns,
            self._generator(directory),
        )
