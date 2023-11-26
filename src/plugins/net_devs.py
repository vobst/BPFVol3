"""
Created by: Ofek Shaked and Amir Sheffer as part of the Volatilty 2021
    plugin context.
https://github.com/volatilityfoundation/community3/tree/master/Sheffer_Shaked_Docker

Modified by: Valentin Obst
"""

"""Volatility3 plugin that displays information about network devices."""

import logging
from collections.abc import Iterable

from volatility3.framework import (
    constants,
    exceptions,
    interfaces,
    renderers,
    symbols,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols.linux import extensions

vollog = logging.getLogger(__name__)


class Ifconfig(interfaces.plugins.PluginInterface):
    """Display information about network devices on the system, similarly to the ifconfig command."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(
        cls,
    ) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @classmethod
    def _get_devs_namespaces(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterable[tuple[int, extensions.net_device]]:
        """Walk the list of net namespaces and extract all net devices from them (kernel >= 2.6.24)."""
        vmlinux = context.modules[vmlinux_module_name]
        symbol_table = vmlinux.symbol_table_name

        net_namespace_list = vmlinux.object_from_symbol(
            symbol_name="net_namespace_list"
        )

        # enumerate each network namespace (struct net) in memory and pass the first one
        for net_ns in net_namespace_list.to_list(
            symbol_table + constants.BANG + "net", "list", sentinel=True
        ):
            try:
                ns_num = net_ns.get_inum()
            except AttributeError:
                ns_num = -1

            # for each net namespace, walk the list of net devices
            for net_dev in net_ns.dev_base_head.to_list(
                symbol_table + constants.BANG + "net_device",
                "dev_list",
                sentinel=True,
            ):
                yield ns_num, net_dev

    @classmethod
    def _get_devs_base(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterable[tuple[int, symbols.linux.extensions.net_device]]:
        """Walk the list of net devices headed by dev_base (kernel < 2.6.22)."""
        vmlinux = context.modules[vmlinux_module_name]

        first_net_device = vmlinux.object_from_symbol(
            symbol_name="dev_base"
        ).dereference()

        for net_dev in symbols.linux.LinuxUtilities.walk_internal_list(
            vmlinux, "net_device", "next", first_net_device
        ):
            # no network namespace, so yield -1 instead of namespace number
            yield -1, net_dev

    @classmethod
    def get_net_devs(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterable[symbols.linux.extensions.net_device]:
        """Get all network devices."""
        vmlinux = context.modules[vmlinux_module_name]

        # kernel >= 2.6.24
        if vmlinux.has_symbol("net_namespace_list"):
            func = cls._get_devs_namespaces
        # kernel < 2.6.22
        elif vmlinux.has_symbol("dev_base"):
            func = cls._get_devs_base
        # kernel 2.6.22 and 2.6.23
        elif vmlinux.has_symbol("dev_name_head"):
            vollog.error(
                "Cannot extract net devices from kernel versions 2.6.22 - 2.6.23"
            )
            return
        # other unsupported kernels
        else:
            vollog.error(
                "Unable to determine ifconfig information. Probably because it's an old kernel"
            )
            return

        # yield net devices
        for net_ns, dev in func(context, vmlinux_module_name):
            yield net_ns, dev

    @classmethod
    def get_miniq_bpf_cls(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        miniq: interfaces.objects.ObjectInterface,
    ) -> list[int]:
        vmlinux = context.modules[vmlinux_module_name]
        symbol_table = vmlinux.symbol_table_name
        ret = []

        if int(miniq) == 0:
            return ret

        # The availability of the cls_bpf_classify symbol in the kernel
        # symbol table depends on CONFIG_NET_CLS_BPF=y. If it was
        # compiled as module we are currently out luck. The feature
        # iteself was introduced in 7d1d65c, v3.13-rc1.
        if not vmlinux.has_symbol("cls_bpf_classify"):
            vollog.error(
                "Cannot extract bpf classifiers from kernel versions"
                "before v3.13-rc1 or with cls_bpf compiled as a module."
            )
            return []

        tcf_proto = miniq.filter_list
        while (
            tcf_proto != 0
            and tcf_proto.classify
            == vmlinux.get_absolute_symbol_address("cls_bpf_classify")
        ):
            cls_bpf_head = vmlinux.object(
                "cls_bpf_head", tcf_proto.root, absolute=True
            )
            for cls_prog in cls_bpf_head.plist.to_list(
                symbol_table + constants.BANG + "cls_bpf_prog", "link"
            ):
                ret.append(int(cls_prog.filter))

            tcf_proto = tcf_proto.next

        return ret

    @classmethod
    def get_net_dev_info(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        net_dev: symbols.linux.extensions.net_device,
    ) -> tuple[str, str, str, int, str, int, bool, list[int], list[int]]:
        """Extract various information from a network device:
        name,
        mac_addr,
        ipv4_addr,
        ipv4_prefixlen,
        ipv6_addr,
        ipv6_prefixlen,
        promisc,
        bpf_cls_ingress,
        bpf_cls_egress,
        """
        vmlinux = context.modules[vmlinux_module_name]
        symbol_table = vmlinux.symbol_table_name

        # get device name
        name = utility.array_to_string(net_dev.name)

        # get MAC address
        mac_addr = ""
        for netdev_hw_addr in net_dev.dev_addrs.list.to_list(
            symbol_table + constants.BANG + "netdev_hw_addr",
            "list",
            sentinel=True,
        ):
            mac_addr = ":".join([f"{x:02x}" for x in netdev_hw_addr.addr][:6])
            # use only first address
            break

        # get IPv4 info
        try:
            first_in_ifaddr = net_dev.get_ip_ptr().ifa_list.dereference()
            ipv4_addr = conversion.convert_ipv4(first_in_ifaddr.ifa_address)
            ipv4_prefixlen = first_in_ifaddr.ifa_prefixlen
        except exceptions.PagedInvalidAddressException:
            ipv4_addr = ""
            ipv4_prefixlen = 0

        # get IPv6 info
        ipv6_addr = ""
        ipv6_prefixlen = 0
        try:
            inet6_dev = net_dev.get_ip6_ptr()

            # get inet6_ifaddr iterator
            try:
                inet6_ifaddrs = inet6_dev.addr_list.to_list(
                    symbol_table + constants.BANG + "inet6_ifaddr",
                    "if_list",
                    sentinel=True,
                )
            # in kernel < 3.0.0, inet6_dev.addr_list is a pointer to the first inet6_ifaddr (as opposed to a list head)
            except AttributeError:
                # each inet6_ifaddr points to the next through 'ifpub'
                inet6_ifaddrs = symbols.linux.LinuxUtilities.walk_internal_list(
                    vmlinux,
                    "inet6_ifaddr",
                    "ifpub",
                    inet6_dev.addr_list.dereference(),
                )

            for inet6_ifaddr in inet6_ifaddrs:
                ipv6_addr = conversion.convert_ipv6(
                    inet6_ifaddr.addr.in6_u.u6_addr32
                )
                ipv6_prefixlen = inet6_ifaddr.prefix_len
                # use only first address
                break
        except exceptions.PagedInvalidAddressException:
            pass

        # get promiscuity
        promisc = bool(net_dev.promiscuity)

        # get bpf classifiers
        bpf_cls_ingress = (
            cls.get_miniq_bpf_cls(
                context, vmlinux_module_name, net_dev.miniq_ingress
            )
            if net_dev.has_member("miniq_ingress")
            else []
        )
        bpf_cls_egress = (
            cls.get_miniq_bpf_cls(
                context, vmlinux_module_name, net_dev.miniq_egress
            )
            if net_dev.has_member("miniq_egress")
            else []
        )

        return (
            name,
            mac_addr,
            ipv4_addr,
            ipv4_prefixlen,
            ipv6_addr,
            ipv6_prefixlen,
            promisc,
            bpf_cls_ingress,
            bpf_cls_egress,
        )

    def _generator(self):
        # get all network devices
        for _, net_dev in self.get_net_devs(
            self.context, self.config["kernel"]
        ):
            # extract information from each device
            info = self.get_net_dev_info(
                self.context, self.config["kernel"], net_dev
            )
            (
                name,
                mac_addr,
                ipv4_addr,
                ipv4_prefixlen,
                ipv6_addr,
                ipv6_prefixlen,
                promisc,
                _,
                _,
            ) = info

            # convert to CIDR notation
            if ipv4_addr:
                ipv4 = ipv4_addr + "/" + str(ipv4_prefixlen)
            else:
                ipv4 = ""

            if ipv6_addr:
                ipv6 = ipv6_addr + "/" + str(ipv6_prefixlen)
            else:
                ipv6 = ""

            yield (0, (name, mac_addr, ipv4, ipv6, promisc))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Name", str),
                ("MAC Address", str),
                ("IPv4 Address", str),
                ("IPv6 Address", str),
                ("Promiscous Mode", bool),
            ],
            self._generator(),
        )
