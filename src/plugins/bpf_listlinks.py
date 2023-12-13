# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
A Volatility3 plugin that tries to display information
typically accessed via bpftool link list subcommand
"""
import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, ClassVar, Optional

from volatility3.framework import constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import RequirementInterface
from volatility3.framework.interfaces.context import (
    ContextInterface,
    ModuleInterface,
)
from volatility3.framework.interfaces.plugins import PluginInterface
from volatility3.framework.renderers import TreeGrid
from volatility3.utility.datastructures import XArray
from volatility3.utility.link import BpfLink

if TYPE_CHECKING:
    from volatility3.framework.interfaces.objects import ObjectInterface

vollog: logging.Logger = logging.getLogger(__name__)


class LinkList(PluginInterface):
    """Lists the BPF links present in a particular Linux memory image"""

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
                description="Filter on specific BPF link IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _generator(
        self,
        filter_func: Callable[[BpfLink], bool] = lambda _: False,
    ) -> Iterable[tuple[int, tuple]]:
        """Generates the BPF link list
        Args:
            filter_func: A function which takes a BPF link object and
                returns True if the link should be ignored/filtered
        Yields:
            Each row
        """
        for link in self.list_links(
            self.context, self.config["kernel"], filter_func
        ):
            yield (0, link.row())

    @classmethod
    def list_links(
        cls,
        context: ContextInterface,
        vmlinux_module_name: str = "kernel",
        filter_func: Callable[[BpfLink], bool] = lambda _: False,
    ) -> Iterable[BpfLink]:
        """Lists all the BPF links in the primary layer
        Args:
            context: The context to retrieve required elements
                (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which
                to operate
            filter_func: A function which takes a BPF links object and
                returns True if the links should be ignored/filtered
        Yields:
            BPF links objects
        """
        vmlinux: ModuleInterface = context.modules[vmlinux_module_name]

        # bpf links were introduced in 70ed506, v5.7-rc1
        if not vmlinux.has_type("bpf_link"):
            vollog.log(
                constants.LOGLEVEL_V,
                "Kernel versions < 5.7-rc1 have no BPF links",
            )
            return []

        # IDR for links was introduced in a3b80e1, v5.8-rc1
        if not vmlinux.has_symbol("link_idr"):
            vollog.log(
                constants.LOGLEVEL_V,
                "Listing links is only supported for Linux version >= 5.8-rc1",
            )
            return []

        link_idr: ObjectInterface = vmlinux.object_from_symbol(
            symbol_name="link_idr"
        )

        xarray: XArray = XArray(link_idr.idr_rt, "bpf_link", context)

        for link in xarray.xa_for_each():
            link: BpfLink = BpfLink(link, context)  # noqa: PLW2901
            if filter_func(link):
                continue
            yield link

    @classmethod
    def create_filter(
        cls,
        id_list: Optional[list[int]] = None,
    ) -> Callable[[BpfLink], bool]:
        """Constructs a filter function for BPF links
        Args:
            id_list: List of BPF link IDs that are acceptable
                (or None if all are acceptable)
        Returns:
            Function which, when provided a BPF link object, returns True
            iff the link is to be filtered out of the list
        """
        id_list = id_list or []
        id_filter_list: list[int] = [x for x in id_list if x is not None]
        if id_filter_list:

            def filter_func(link: BpfLink) -> bool:
                return int(link.link.id) not in id_filter_list

            return filter_func

        return lambda _: False

    def run(self) -> TreeGrid:
        columns: list[tuple[str, type]] = [
            ("OFFSET (V)", str),
            ("ID", int),
            ("TYPE", str),
            ("PROG", int),
            ("ATTACH", str),
        ]

        filter_func: Callable[[BpfLink], bool] = self.create_filter(
            self.config.get("id", None)
        )

        return TreeGrid(
            columns,
            self._generator(filter_func),
        )
