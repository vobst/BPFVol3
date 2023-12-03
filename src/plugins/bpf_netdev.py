# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
Displays information about tc BPF programs attached to network devices
"""
import logging
from collections.abc import Iterable
from typing import ClassVar

from volatility3.framework import constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.configuration import RequirementInterface
from volatility3.framework.interfaces.context import (
    ContextInterface,
    ModuleInterface,
)
from volatility3.framework.interfaces.objects import ObjectInterface
from volatility3.framework.interfaces.plugins import PluginInterface
from volatility3.framework.renderers import TreeGrid
from volatility3.framework.symbols.linux import LinuxUtilities
from volatility3.framework.symbols.linux.extensions import net_device
from volatility3.plugins.linux.ifconfig import Ifconfig
from volatility3.utility.prog import BpfProg

vollog: logging.Logger = logging.getLogger(__name__)


class BpfClsList(PluginInterface):
    """Displays information about BPF programs attached to network devices"""

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
                name="net_devs",
                plugin=Ifconfig,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def get_miniq_bpf_cls(
        cls,
        context: ContextInterface,
        vmlinux_module_name: str,
        miniq: ObjectInterface,  # struct mini_Qdisc
    ) -> list[BpfProg]:
        """Returns all BPF filters attached to the given qdisc"""
        vmlinux: ModuleInterface = context.modules[vmlinux_module_name]
        symbol_table: str = vmlinux.symbol_table_name
        ret: list[BpfProg] = []

        if int(miniq) == 0:
            return ret

        # The availability of the cls_bpf_classify symbol in the kernel
        # symbol table depends on CONFIG_NET_CLS_BPF=y. If it was
        # compiled as module we are currently out luck. The feature
        # iteself was introduced in 7d1d65c, v3.13-rc1
        if not vmlinux.has_symbol("cls_bpf_classify"):
            vollog.error(
                "Cannot extract BPF classifiers from kernel versions "
                "before v3.13-rc1 or with cls_bpf compiled as a module."
            )
            return []

        fn_cls_bpf_classify: int = vmlinux.get_absolute_symbol_address(
            "cls_bpf_classify"
        )

        tcf_proto: ObjectInterface = miniq.filter_list
        while int(tcf_proto) != 0:
            if tcf_proto.classify != fn_cls_bpf_classify:
                continue

            cls_bpf_head: ObjectInterface = vmlinux.object(
                "cls_bpf_head", tcf_proto.root, absolute=True
            )
            for cls_prog in cls_bpf_head.plist.to_list(
                symbol_table + constants.BANG + "cls_bpf_prog", "link"
            ):
                ret.append(BpfProg(cls_prog.filter, context))

            tcf_proto: ObjectInterface = tcf_proto.next

        return ret

    @classmethod
    def list_bpf_cls(
        cls,
        context: ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterable[
        tuple[ObjectInterface, net_device, list[BpfProg], list[BpfProg]]
    ]:
        vmlinux: ModuleInterface = context.modules[vmlinux_module_name]

        for ns, net_dev in Ifconfig.get_net_devs(context, vmlinux_module_name):
            # get bpf classifiers
            if net_dev.has_member("miniq_egress"):
                # <6.6 && CONFIG_NET_CLS_ACT
                miniq_egress = net_dev.miniq_egress
                miniq_ingress = net_dev.miniq_ingress
            elif net_dev.has_member("tcx_egress"):
                # >=6.6 && CONFIG_NET_XGRESS, e420bed
                entry_egress = LinuxUtilities.container_of(
                    int(net_dev.tcx_egress.parent),
                    "tcx_entry",
                    "bundle",
                    vmlinux,
                )
                assert entry_egress is not None
                miniq_egress: ObjectInterface = entry_egress.miniq

                entry_ingress = LinuxUtilities.container_of(
                    int(net_dev.tcx_ingress.parent),
                    "tcx_entry",
                    "bundle",
                    vmlinux,
                )
                assert entry_ingress is not None
                miniq_ingress: ObjectInterface = entry_ingress.miniq
            else:
                vollog.error("Unsupported kernel")
                break

            bpf_cls_ingress: list[BpfProg] = cls.get_miniq_bpf_cls(
                context, vmlinux_module_name, miniq_ingress
            )
            bpf_cls_egress: list[BpfProg] = cls.get_miniq_bpf_cls(
                context, vmlinux_module_name, miniq_egress
            )

            if not bpf_cls_egress and not bpf_cls_ingress:
                continue

            yield ns, net_dev, bpf_cls_egress, bpf_cls_ingress

    def _generator(
        self,
    ) -> Iterable[tuple[int, tuple[str, str, str, str]]]:
        for _, net_dev, bpf_cls_egress, bpf_cls_ingress in self.list_bpf_cls(
            self.context, self.config["kernel"]
        ):
            name, mac_addr, *_ = Ifconfig.get_net_dev_info(
                self.context, self.config["kernel"], net_dev
            )

            yield (
                0,
                (
                    str(name),
                    str(mac_addr),
                    ",".join(str(prog.aux.id) for prog in bpf_cls_egress),
                    ",".join(str(prog.aux.id) for prog in bpf_cls_ingress),
                ),
            )

    def run(self) -> TreeGrid:
        columns: list[tuple[str, type]] = [
            ("NAME", str),
            ("MAC ADDR", str),
            ("EGRESS", str),
            ("INGRESS", str),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )
