# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
This module contains functionality to display general information about BPF
links
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING

from volatility3.framework import constants
from volatility3.framework.objects.utility import pointer_to_string
from volatility3.framework.symbols.linux import LinuxUtilities
from volatility3.utility.helpers import get_object, make_vol_type

if TYPE_CHECKING:
    from volatility3.framework.interfaces.context import (
        ContextInterface,
        ModuleInterface,
    )
    from volatility3.framework.interfaces.objects import ObjectInterface

vollog: logging.Logger = logging.getLogger(__name__)

MAX_STR_LEN: int = 256


class BpfLink:
    def __init__(
        self,
        link: ObjectInterface | int,
        context: ContextInterface,
    ) -> None:
        # our caller might give us a pointer to any type, lets unify it
        if isinstance(link, int):
            self.link = get_object("bpf_link", link, context)
        else:
            self.link: ObjectInterface = (
                link
                if link.vol.type_name == make_vol_type("bpf_link", context)
                else link.dereference().cast("bpf_link")
            )
        self.context: ContextInterface = context
        self.vmlinux: ModuleInterface = self.context.modules["kernel"]

        self.attach_types = Enum(
            "BpfAttachType",
            names=self.vmlinux.get_enumeration(
                "bpf_attach_type"
            ).choices.items(),
        )
        self.types = Enum(
            "BpfLinkType",
            names=self.vmlinux.get_enumeration("bpf_link_type").choices.items(),
        )
        self.type = self.types(self.link.type)

        self.prog: ObjectInterface = self.link.prog.dereference().cast(
            "bpf_prog"
        )

    @property
    def label(self) -> str:
        return f"{self.link.id}/{';'.join(self.get_fill_link_info())}"

    def row(self):
        return (
            hex(self.link.vol.offset),
            int(self.link.id),
            str(self.type).removeprefix("BpfLinkType.BPF_LINK_TYPE_"),
            int(self.prog.aux.id),
            ";".join(self.get_fill_link_info()),
        )

    def get_fill_link_info(self) -> list[str]:
        ret: list[str] = []

        fill_link_info_fn: int = int(self.link.ops.fill_link_info)
        if fill_link_info_fn == 0:
            vollog.log(
                constants.LOGLEVEL_V,
                "fill_link_info is NULL",
            )
            return ret

        fill_link_info_fn_name: str = (
            self.vmlinux.get_symbols_by_absolute_location(fill_link_info_fn)[
                0
            ].split(constants.BANG)[1]
        )
        match fill_link_info_fn_name:
            case "bpf_nf_link_fill_link_info":
                # added in v6.4-rc1, 84601d6
                # https://lore.kernel.org/all/20230421170300.24115-1-fw@strlen.de/
                pass  # TODO: gen. test image once I have VM w/ newer kernel
            case "bpf_cgroup_link_fill_link_info":
                ret = self._fill_cg()
            case "bpf_raw_tp_link_fill_link_info":
                ret = self._fill_rawtp()
            case "bpf_tracing_link_fill_link_info":
                ret = self._fill_tracing()
            case "bpf_struct_ops_map_link_fill_link_info":
                # TODO: convince libbpf to generate this link type
                pass
            case "bpf_iter_link_fill_link_info":
                ret = self._fill_iter()
            case "bpf_netns_link_fill_info":
                ret = self._fill_netns()
            case "bpf_xdp_link_fill_link_info":
                ret = self._fill_xdp()
            case _:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"Unknown fill_link_info: {fill_link_info_fn_name}",
                )

        return ret

    def _fill_netns(self) -> list[str]:
        net_link: ObjectInterface | None = self._downcast("bpf_netns_link")
        if net_link is None:
            return []

        inum: int = int(net_link.net.ns.inum)
        attach_type: str = str(self.attach_types(net_link.type)).removeprefix(
            "BpfAttachType.BPF_"
        )

        return [f"{inum=}", f"{attach_type=}"]

    def _fill_cg(self) -> list[str]:
        cg_link: ObjectInterface | None = self._downcast("bpf_cgroup_link")
        if cg_link is None:
            return []

        attach_type: str = str(self.attach_types(cg_link.type)).removeprefix(
            "BpfAttachType.BPF_"
        )
        cgroup_id: int = int(cg_link.cgroup.kn.id)

        return [f"{attach_type=}", f"{cgroup_id=}"]

    def _fill_rawtp(self) -> list[str]:
        rawtp_link: ObjectInterface | None = self._downcast("bpf_raw_tp_link")
        if rawtp_link is None:
            return []

        tp_name: str = str(
            pointer_to_string(rawtp_link.btp.tp.name, MAX_STR_LEN)
        )

        return [f"{tp_name=}"]

    def _fill_xdp(self) -> list[str]:
        xdp_link: ObjectInterface | None = self._downcast("bpf_xdp_link")
        if xdp_link is None:
            return []

        ifindex: int = int(xdp_link.dev.ifindex)

        return [f"{ifindex=}"]

    def _fill_tracing(self) -> list[str]:
        tr_link: ObjectInterface | None = self._downcast("bpf_tracing_link")
        if tr_link is None:
            return []

        attach_type: str = str(
            self.attach_types(tr_link.attach_type)
        ).removeprefix("BpfAttachType.BPF_")

        key: int = int(tr_link.trampoline.key)
        obj_id, btf_id = key >> 32, key & 0x7FFFFFFF

        return [f"{attach_type=}", f"{obj_id=}", f"{btf_id=}"]

    def _fill_iter(self) -> list[str]:
        it_link: ObjectInterface | None = self._downcast("bpf_iter_link")
        if it_link is None:
            return []

        target_name: str = str(
            pointer_to_string(it_link.tinfo.reg_info.target, MAX_STR_LEN)
        )

        return [f"{target_name=}"]

    def _downcast(self, outer_link_name: str) -> ObjectInterface | None:
        return LinuxUtilities.container_of(
            int(self.link.vol.offset),
            outer_link_name,
            "link",
            self.vmlinux,
        )
