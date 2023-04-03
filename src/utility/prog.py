"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT

This file contains functionality to display general information
about BPF programs and to dump their code
"""
from __future__ import annotations

import logging
import re
from typing import (
    Iterable,
    Optional,
    Tuple,
    List,
    Set,
    Any,
    Dict,
    Callable,
    cast,
)
from collections import namedtuple
from itertools import chain
from capstone import (
    Cs,
    CsError,
    CS_MODE_64,
    CS_MODE_BPF_EXTENDED,
    CS_ARCH_X86,
    CS_ARCH_BPF,
)
from enum import Enum, Flag

from volatility3.framework.symbols.linux import extensions
from volatility3.framework import constants
from volatility3.framework.objects.utility import (
    array_of_pointers,
    array_to_string,
    pointer_to_string,
)
from volatility3.framework import interfaces
from volatility3.utility.helpers import (
    make_vol_type,
    get_vol_template,
)

from volatility3.plugins.linux.net_devs import Ifconfig

from volatility3.utility.btf import Btf, BtfException
from volatility3.utility.map import BpfMap
from volatility3.utility.datastructures import XArray
from volatility3.utility.enums import TraceEventFlag
from volatility3.framework.symbols.linux import LinuxUtilities

vollog = logging.getLogger(__name__)


# represents a symbol that is referenced within a BPF program
BpfProgSym = namedtuple("BpfProgSym", ["name", "kind"])

# the different kinds of symbols that might appear in a BPF program
class BpfProgSymKind(Enum):
    MAIN = 1
    FUNC = 2
    HELPER = 3
    MAP = 4


class BpfProg:
    def __init__(
        self,
        prog: interfaces.objects.ObjectInterface,
        context: interfaces.context.ContextInterface,
    ):
        self.prog = (
            prog
            if prog.vol.type_name == make_vol_type("bpf_prog", context)
            else prog.dereference().cast("bpf_prog")
        )
        self.context = context
        self.vmlinux = self.context.modules["kernel"]
        self.types = Enum(
            "BpfProgType",
            names=self.vmlinux.get_enumeration(
                "bpf_prog_type"
            ).choices.items(),
        )

        self.aux = self.prog.aux
        self.type = self.types(self.prog.type)

        try:
            # btf info for programs was introduced in 838e969, v5.0-rc1
            if not self.aux.has_valid_member("btf"):
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Kernel version before v5.0-rc1 does not support"
                    "prog BTF",
                )
                raise BtfException
            # BTF is nice-to-have, but a program is not required to
            # have it
            elif int(self.aux.btf) == 0:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Program does not have BTF info attached",
                )
                raise BtfException
            else:
                self.btf = Btf(self.aux.btf, context)
        except BtfException:
            self.btf = None

        # lazy init
        self._link = None
        self._attach_type = None
        self._attach_to = None
        self._net_dev = None
        self._mcode = None
        self._mdisasm = None
        self._bcode = None
        self._bdisasm = None
        self._funcs = None
        self._symbol_table = None
        self._name = None
        self._maps = None

    @property
    def name(self):
        if self._name:
            return self._name

        if self.aux.has_valid_member("func_info") and self.btf:
            func_info = self.aux.func_info.dereference().cast(
                "array",
                count=(
                    1 if self.aux.func_cnt == 0 else self.aux.func_cnt
                ),
                subtype=get_vol_template("bpf_func_info", self.context),
            )
            self._name = self.btf.get_string(
                func_info[self.aux.func_idx].type_id
            )
        else:
            self._name = str(array_to_string(self.aux.name))

        return self._name

    @property
    def symbol_table(self) -> Dict[int, BpfProgSym]:
        if self._symbol_table:
            return self._symbol_table
        ret = dict()
        # add the main program
        ret.update(
            {
                int(self.prog.bpf_func): BpfProgSym(
                    self.name, BpfProgSymKind.MAIN
                )
            }
        )
        # add all functions
        for func in self.funcs:
            ret.update(
                {
                    int(func.prog.bpf_func): BpfProgSym(
                        func.name, BpfProgSymKind.FUNC
                    )
                }
            )
        # add all maps (accesses to array maps may be jited to direct
        # memory loads and stores, i.e., they are not performed
        # through an accesor function that accepts a pointer to
        # the bpf_map object)
        for m in self.maps:
            ret.update(
                {
                    int(m.map.vol.get("offset"))
                    + 0xFFFF000000000000: BpfProgSym(
                        m.name, BpfProgSymKind.MAP
                    )
                }
            )
        # all calls to kernel functions
        for i in chain(
            self.mdisasm, *(func.mdisasm for func in self.funcs)
        ):
            if i.insn_name() == "call":
                # check if we already have a symbol for the address
                if ret.get(int(i.op_str, 16), None):
                    continue
                try:  # to resolve helper by mapping address->symbol
                    ret.update(
                        {
                            int(i.op_str, 16): BpfProgSym(
                                self.vmlinux.get_symbols_by_absolute_location(
                                    int(i.op_str, 16)
                                )[
                                    0
                                ].split(
                                    constants.BANG
                                )[
                                    1
                                ],
                                BpfProgSymKind.HELPER,
                            )
                        }
                    )
                except Exception as E:
                    # there should always be a symbol as bpf2bpf calls
                    # are already resolved
                    vollog.info(
                        constants.LOGLEVEL_V,
                        f"BUG: Unable to resolve address of call {i} ({E})",
                    )

        self._symbol_table = ret
        return self._symbol_table

    @property
    def funcs(self) -> List[BpfProg]:
        """A 'main' BPF program may call functions that are also
        implemented im BPF, i.e. BPF2BPF calls. This returns the list
        of all such 'function programs'"""
        if self._funcs:
            return self._funcs

        # support for multi func programs was added in 1c2a088,
        # v4.16-rc1 (for amd64)
        if self.aux.has_valid_member("func") and self.aux.func_cnt > 0:
            func_ptrs = array_of_pointers(
                self.aux.func.dereference(),
                self.aux.func_cnt,
                make_vol_type("bpf_prog", self.context),
                self.context,
            )
            # the first entry is the main program itself, which we do
            # not want to include here
            self._funcs = [
                BpfProg(prog, self.context) for prog in func_ptrs[1:]
            ]
        else:
            self._funcs = []

        return self._funcs

    def __eq__(self, other: BpfProg) -> bool:
        return self.prog.vol.get("offset") == other.prog.vol.get(
            "offset"
        )

    def row(self):
        """Returns:
        The plugin output for this particular program.
        """
        return (
            hex(self.prog.vol.offset),
            int(self.aux.id),
            self.name,
            str(self.type),
            int(self.aux.load_time * 10**-6),
            ",".join(self.helpers),
            ",".join([str(m.map.id) for m in self.maps]),
            str(self.link.type) if self.link else "n.a.",
            str(self.attach_type) if self.attach_type else "n.a.",
            self.attach_to,
        )

    @property
    def attach_to(self) -> str:
        if self._attach_to:
            return self._attach_to
        elif self.link:
            self._attach_to = self.link.attach_to
        elif (
            self.type == self.types.BPF_PROG_TYPE_SCHED_CLS
            and self.net_dev
        ):
            self._attach_to = f"tc/{self.net_dev.dir}/{array_to_string(self.net_dev.name)}"
        else:
            self._attach_to = ""

        return self._attach_to

    @property
    def net_dev(self) -> Optional[extensions.net_device]:
        if self._net_dev:
            return self._net_dev
        for _, net_dev in Ifconfig.get_net_devs(self.context, "kernel"):
            if self.prog.vol.get(
                "offset"
            ) in Ifconfig.get_miniq_bpf_cls(
                self.context, "kernel", net_dev.miniq_egress
            ):
                self._net_dev = net_dev
                setattr(self._net_dev, "dir", "egress")
            if self.prog.vol.get(
                "offset"
            ) in Ifconfig.get_miniq_bpf_cls(
                self.context, "kernel", net_dev.miniq_ingress
            ):
                self._net_dev = net_dev
                setattr(self._net_dev, "dir", "ingress")

        return self._net_dev

    @property
    def attach_type(self):
        """
        Returns: The attach type for programs that are currently
            attached somewhere or None if the program is not attached/we
            can't figure it out.
        """
        if self._attach_type:
            return self._attach_type
        if self.link:
            self._attach_type = self.link.attach_type
        return self._attach_type

    def dump_mcode(self) -> str:
        re_imm = re.compile(r"^.*?(0xffff[0-9a-f]+?)$")
        ret = []
        for i in chain(
            self.mdisasm, *(func.mdisasm for func in self.funcs)
        ):
            # annotate above the line, e.g. the beginning of functions
            symbol = self.symbol_table.get(i.address, None)
            if symbol:
                ret.append(f"\n{symbol.name}:")
            # annotate at the end of the line
            end = ""

            imm = re.search(re_imm, i.op_str)
            if imm:
                sym_off = self.get_symbol(int(imm.group(1), 16))
                if sym_off:
                    end = (
                        "\t# "
                        + f"{sym_off[0].name}"
                        + (
                            f" + {hex(sym_off[1])}"
                            if sym_off[1]
                            else ""
                        )
                    )

            ret.append(
                f" {hex(i.address)}: "
                f"{' '.join(map(lambda n: format(n, '02x'), list(i.bytes)))}"
                + (15 - i.size) * "   "
                + f" {i.mnemonic} "
                f"{i.op_str}"
                f"{end}"
            )

        return "\n".join(ret)

    def get_symbol(
        self, address: int
    ) -> Optional[Tuple[BpfProgSym, int]]:
        """returns:
        The closest preceeding symbol in the program (within somewhat
        arbitrary bounds, to balance false positives and false
        negatives) along with its distance from the given address.
        """
        max_dist = 4096
        current = (None, max_dist + 1)
        for saddr, symbol in self.symbol_table.items():
            dist = address - saddr
            if dist < 0:
                continue
            if dist == 0:
                return (symbol, 0)
            if dist < current[1]:
                current = (symbol, dist)

        return current if current[0] != None else None

    def dump_bcode(self) -> str:
        ret = []
        for i in self.bdisasm:
            ret.append(
                f"{hex(i.address)}: "
                f"{' '.join(map(lambda n: format(n, '02x'), list(i.bytes)))}"
                + (16 - i.size) * "   "
                + f" {i.mnemonic} "
                f"{i.op_str}"
            )
        return "\n".join(ret)

    @property
    def link(self) -> Optional[BpfLink]:
        """Returns:
        A link that references the program or None.
        """
        if self._link:
            return self._link
        for link in LinkList.list_links(self.context):
            if link.prog.prog.vol.offset == self.prog.vol.offset:
                self._link = link
                return link

    @property
    def mcode(self) -> bytes:
        """Returns:
        Machine code of the program."""
        if self._mcode:
            return self._mcode
        else:
            self._mcode = bytes(
                self.context.layers.read(
                    self.vmlinux.layer_name,
                    self.prog.bpf_func,
                    self.prog.jited_len,
                )
            )
        return self._mcode

    @property
    def bcode(self) -> bytes:
        """Returns:
        Bytecode of the program."""
        if self._bcode:
            return self._bcode
        else:
            self._bcode = bytes(
                self.context.layers.read(
                    self.vmlinux.layer_name,
                    self.prog.insnsi.vol.get("offset"),
                    self.prog.len * 8,
                )
            )
        return self._bcode

    @property
    def maps(self) -> List[BpfMap]:
        """Returns:
        Maps used by the program."""
        if self._maps:
            return self._maps
        if self.aux.used_map_cnt > 0:
            map_ptrs = array_of_pointers(
                self.aux.used_maps.dereference(),
                self.aux.used_map_cnt,
                make_vol_type("bpf_map", self.context),
                self.context,
            )
            self._maps = [BpfMap(m, self.context) for m in map_ptrs]
        else:
            self._maps = []

        return self._maps

    @property
    def bdisasm(self) -> Iterable[Any]:
        if self._bdisasm:
            return self._bdisasm
        else:
            try:
                md = Cs(CS_ARCH_BPF, CS_MODE_BPF_EXTENDED)
                self._bdisasm = list(md.disasm(self.bcode, 0))
            except CsError as E:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"Unable to disassemble jited program id={self.aux.id} "
                    f"({E})",
                )
                self._bdisasm = []
        return self._bdisasm

    @property
    def mdisasm(self) -> List[Any]:
        if self._mdisasm:
            return self._mdisasm
        else:
            try:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                self._mdisasm = list(
                    md.disasm(self.mcode, int(self.prog.bpf_func))
                )
            except CsError as E:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"Unable to disassemble jited program id={self.aux.id} "
                    f"({E})",
                )
                self._mdisasm = []
        return self._mdisasm

    @property
    def helpers(self) -> Set[str]:
        """Returns:
        Set of all BPF helper, kfunc and BPF2BPF calls that happen in
        the program."""
        return set(
            symbol.name
            for symbol in self.symbol_table.values()
            if symbol.kind == BpfProgSymKind.HELPER
        )


# Links have to work with programs, and programs have to
# work with links - thus they are both in this file together.
class BpfLink:
    """Wraps a struct bpf_link to, e.g., determine its attachment
    point"""

    def __init__(
        self,
        link: interfaces.objects.ObjectInterface,
        context: interfaces.context.ContextInterface,
    ):
        # our caller might give us a pointer to any type, lets unify it
        self.link = (
            link
            if link.vol.type_name == make_vol_type("bpf_link", context)
            else link.dereference().cast("bpf_link")
        )
        self.context = context
        self.vmlinux = self.context.modules["kernel"]
        self.types = Enum(
            "BpfLinkType",
            names=self.vmlinux.get_enumeration(
                "bpf_link_type"
            ).choices.items(),
        )
        self.attach_types = Enum(
            "BpfAttachType",
            names=self.vmlinux.get_enumeration(
                "bpf_attach_type"
            ).choices.items(),
        )

        self.prog = BpfProg(
            self.link.prog.dereference().cast("bpf_prog"), self.context
        )
        self.type = self.types(self.link.type)
        self.typed_link = self._get_typed_link()
        self._attach_type = None

    def _get_typed_link(
        self,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Tries to map a bpf_link to the, more specific,
        surrounding bpf_.*?_link using its .type (not sure if this
        is possible).
        """
        match self.type:
            case self.types.BPF_LINK_TYPE_ITER:
                outer_link_name = "bpf_iter_link"
            case self.types.BPF_LINK_TYPE_PERF_EVENT:
                outer_link_name = "bpf_perf_link"
            case self.types.BPF_LINK_TYPE_KPROBE_MULTI:
                outer_link_name = "bpf_kprobe_multi_link"
            case self.types.BPF_LINK_TYPE_RAW_TRACEPOINT:
                outer_link_name = "bpf_raw_tp_link"
            case self.types.BPF_LINK_TYPE_TRACING:
                outer_link_name = "bpf_tracing_link"
            case self.types.BPF_LINK_TYPE_CGROUP:
                outer_link_name = "bpf_cgroup_link"
            case self.types.BPF_LINK_TYPE_NETNS:
                outer_link_name = "bpf_netns_link"
            case self.types.BPF_LINK_TYPE_XDP:
                outer_link_name = "bpf_xdp_link"
            case self.types.BPF_LINK_TYPE_STRUCT_OPS:
                outer_link_name = "bpf_tramp_link"
            case _:
                vollog.warning(
                    constants.LOGLEVEL_V,
                    "Bug or kernel update.",
                )
                return None
        return LinuxUtilities.container_of(
            int(self.link.vol.offset),
            outer_link_name,
            "link",
            self.vmlinux,
        )

    @property
    def attach_type(self):
        """Returns: The attach type of the link's program"""
        if self._attach_type:
            return self._attach_type
        if not self.typed_link:
            return None
        match self.typed_link.vol.get("type_name").split(
            constants.BANG
        )[1]:
            case "bpf_iter_link":
                self._attach_type = self.attach_types.BPF_TRACE_ITER
            case "bpf_perf_link":
                self._attach_type = self.attach_types.BPF_PERF_EVENT
            case "bpf_kprobe_multi_link":
                self._attach_type = (
                    self.attach_types.BPF_TRACE_KPROBE_MULTI
                )
            case "bpf_raw_tp_link":
                self._attach_type = self.attach_types.BPF_TRACE_RAW_TP
            case "bpf_tracing_link":
                self._attach_type = self.attach_types(
                    int(self.typed_link.attach_type)
                )
            case "bpf_cgroup_link" | "bpf_netns_link":
                self._attach_type = self.attach_types(
                    int(self.typed_link.type)
                )
            case "bpf_xdp_link":
                self._attach_type = self.attach_types.BPF_XDP
            case "bpf_tramp_link":
                pass
            case _:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Bug or kernel update.",
                )
        return self._attach_type

    @property
    def attach_to(self) -> str:
        """This method tries its very best to figure out which event the
        link refers to.
        Returns:
            If possible, it tries to return the section name that you
            would specify in a BPF ELF file in order to use libbpf's
            auto-attach feature.
            Whenever that's not possible, the return value is whatever
            I deem descriptive and helpful.
        """
        match self.type:
            case self.types.BPF_LINK_TYPE_ITER:
                if not self.typed_link:
                    vollog.warning(
                        f"Bug or kernel update.",
                    )
                    return ""
                return f"iter/{pointer_to_string(self.typed_link.tinfo.reg_info.target, 9999)}"

            case self.types.BPF_LINK_TYPE_CGROUP:
                if not self.typed_link:
                    vollog.warning(
                        f"Bug or kernel update.",
                    )
                    return ""
                return f"{cgroup/pointer_to_string(self.typed_link.cgroup.kn.name, 9999)}"

            case self.types.BPF_LINK_TYPE_PERF_EVENT:
                s = ""
                match self.prog.type:
                    case self.prog.types.BPF_PROG_TYPE_KPROBE:
                        s += "kprobe/"
                    case self.prog.types.BPF_PROG_TYPE_PERF_EVENT:
                        s += "perf_event/"
                    case self.prog.types.BPF_PROG_TYPE_TRACEPOINT:
                        if not self.typed_link:
                            vollog.log(
                                constants.LOGLEVEL_V,
                                f"Bug or kernel update.",
                            )
                            return s
                        trace_event_call = (
                            self.typed_link.perf_file.private_data.dereference()
                            .cast("perf_event")
                            .tp_event
                        )
                        flags = TraceEventFlag(trace_event_call.flags)
                        if (
                            flags
                            & TraceEventFlag.TRACE_EVENT_FL_TRACEPOINT
                        ):
                            s += f"tp/{pointer_to_string(trace_event_call.tp.name, 9999)}"
                        else:
                            s += f"tp/{pointer_to_string(trace_event_call.name, 9999)}"
                    case _:
                        vollog.log(
                            constants.LOGLEVEL_V,
                            f"Bug or kernel update.",
                        )
                return s
            case _:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"BPF link type not (yet) supported: {self.type}",
                )
                return ""


class LinkList:
    """Lists the BPF links present in a particular Linux memory image."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
    ):
        self.context = context

    @classmethod
    def list_links(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str = "kernel",
        filter_func: Callable[[BpfLink], bool] = lambda _: False,
    ) -> Iterable[BpfLink]:
        vmlinux = context.modules[vmlinux_module_name]
        # bpf links were introduced in 70ed506, v5.7-rc1
        if not vmlinux.has_type("bpf_link"):
            vollog.log(
                constants.LOGLEVEL_V,
                "Kernel version has no BPF links",
            )
            return []
        # IDR for links was introduced in a3b80e1, v5.8-rc1
        if vmlinux.has_symbol("link_idr"):
            link_idr = vmlinux.object_from_symbol(
                symbol_name="link_idr"
            )
        else:
            vollog.log(
                constants.LOGLEVEL_V,
                "Kernel version not (yet) supported",
            )
            return []

        xarray = XArray(link_idr.idr_rt, "bpf_link", context)

        for link in xarray.xa_for_each():
            if filter_func(cast(BpfLink, link)):
                continue
            yield BpfLink(link, context)
