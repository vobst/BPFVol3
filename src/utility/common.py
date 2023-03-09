"""Common script functionality"""
from __future__ import annotations
import logging
from typing import Iterable, Optional, Tuple, List, Set, Any, Dict
from json import dumps
from itertools import chain
from capstone import (
    Cs,
    CsError,
    CS_MODE_64,
    CS_MODE_BPF_EXTENDED,
    CS_ARCH_X86,
    CS_ARCH_BPF,
)
from datetime import datetime

from enum import Enum, Flag
from volatility3.framework.symbols.linux import extensions
from volatility3.framework import constants
from volatility3.framework.objects.utility import *
from volatility3.framework import interfaces

from volatility3.plugins.linux.net_devs import Ifconfig

vollog = logging.getLogger(__name__)


# TODO: not good that we hard code "kernel" here
def make_vol_type(
    name: str,
    context: interfaces.context.ContextInterface,
) -> str:
    """Prepend symbol table to type name."""
    vmlinux = context.modules["kernel"]
    return str(vmlinux.symbol_table_name + constants.BANG + name)


def get_vol_template(
    name: str,
    context: interfaces.context.ContextInterface,
) -> interfaces.objects.Template:
    """Get the template for a type name."""
    vmlinux = context.modules["kernel"]
    return vmlinux.get_type(make_vol_type(name, context))


def get_object(
    name: str,
    offset: int,
    context: interfaces.context.ContextInterface,
) -> interfaces.objects.ObjectInterface:
    """Construct object from type name and offset."""
    vmlinux = context.modules["kernel"]
    return vmlinux.object(name, offset, absolute=True)


# TODO now available under:
# volatility3.framework.symbols.linux.LinuxUtilities
def container_of(
    addr: int,
    type_name: str,
    member_name: str,
    context: interfaces.context.ContextInterface,
) -> Optional[interfaces.objects.ObjectInterface]:
    """Cast a member of a structure out to the containing structure.
    It mimicks the Linux kernel macro container_of() see
    include/linux.kernel.h
    Args:
        addr: The pointer to the member.
        type_name: The type of the container struct this is embedded in.
        member_name: The name of the member within the struct.
        vmlinux: The kernel symbols object
    Returns:
        The constructed object or None
    """
    if not addr:
        return
    type_dec = get_vol_template(type_name, context)
    member_offset = type_dec.relative_child_offset(member_name)
    container_addr = addr - member_offset
    return get_object(type_name, container_addr, context)


def ns_since_boot2datetime(ns_since_boot: int):
    """TODO: See declined pull request
    https://github.com/volatilityfoundation/volatility3/pull/606
    And the Vol2 feature:
    https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/linux/common.py#L253
    """
    return datetime.today()


class XArray:
    """Oversimplified and incomplete iterator for XArrays of pointers"""

    XA_CHUNK_SHIFT = 6  # correct for CONFIG_BASE_SMALL = 0
    XA_CHUNK_SIZE = 1 << XA_CHUNK_SHIFT
    XA_CHUNK_MASK = XA_CHUNK_SIZE - 1

    def __init__(
        self,
        xarray: interfaces.objects.ObjectInterface,
        subtype: str,
        context: interfaces.context.ContextInterface,
    ):
        """
        Args:
            xarray: The xarray to iterate over
            subtype: The type pointed to by array entries
            context: The context to retrieve required elements
              (layers, symbol tables) from
        """
        self.xarray = xarray
        self.subtype = subtype
        self.context = context
        self.xas_node = self.xa_to_node(int(self.xarray.xa_head))
        self.xas_offset = 0

    def _construct_subtype_obj(
        self, entry: int
    ) -> interfaces.objects.ObjectInterface:
        return get_object(self.subtype, entry, self.context)

    def xa_is_node(self, entry: int) -> bool:
        return self.xa_is_internal(entry) and entry > 0x1000

    def xa_is_internal(self, entry: int) -> bool:
        return (entry & 0b11) == 0b10

    def xa_to_node(
        self, entry: int
    ) -> interfaces.objects.ObjectInterface:
        return get_object("xa_node", entry - 0b10, self.context)

    def xa_is_pointer(self, entry: int) -> bool:
        return (entry & 0b11) == 0b00 and entry != 0

    def xas_valid(self) -> bool:
        if self.xas_offset_valid() and self.xas_node_valid():
            return True
        return False

    def xas_offset_valid(self) -> bool:
        if self.xas_offset in range(0, self.XA_CHUNK_SIZE):
            return True
        return False

    def xas_node_valid(self) -> bool:
        if not isinstance(
            self.xas_node, interfaces.objects.ObjectInterface
        ):
            return False
        if (
            self.xas_node.vol.type_name.split(constants.BANG)[1]
            != "xa_node"
        ):
            return False
        if int(self.xas_node.vol.offset) == 0:
            return False
        return True

    def xas_get_entry_from_offset(self) -> Optional[int]:
        if not self.xas_valid():
            return None
        entry = int(self.xas_node.slots[self.xas_offset])
        if self.xa_is_node(entry) or self.xa_is_pointer(entry):
            return entry
        return None

    def xa_for_each(
        self,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the entries in the XArray.
        Yields:
            Subtype objects
        """
        entry = int(self.xarray.xa_head)

        if self.xa_is_node(entry):
            self.xas_node = self.xa_to_node(entry)
            self.xas_offset = 0

            entry = self.xas_descend()
            while entry:
                yield entry
                entry = self.xas_descend()
        elif self.xa_is_pointer(entry):
            yield self._construct_subtype_obj(entry)
        else:
            vollog.log(
                constants.LOGLEVEL_V,
                f"Possibly corrupted XArray at {self.xarray.vol.offset}",
            )

    def xas_descend(
        self,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        entry = None

        while entry == None:
            entry = self.xas_get_entry_from_offset()
            if entry == None:
                self.xas_offset += 1
                while not self.xas_offset_valid():
                    self.xas_offset = self.xas_node.offset + 1
                    self.xas_node = (
                        self.xas_node.parent.dereference().cast(
                            "xa_node"
                        )
                    )
                if not self.xas_node_valid():
                    break
                continue
            elif self.xa_is_node(entry):
                self.xas_node = self.xa_to_node(entry)
                self.xas_offset = 0
                entry = None
                continue
            elif self.xa_is_pointer(entry):
                self.xas_offset += 1
                entry = self._construct_subtype_obj(entry)
            else:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"Possibly corrupted XArray at {self.xarray.vol.offset}",
                )

        return entry


class BtfKind(Enum):
    """TODO: Can I get variants of unnamed enums from symbols?"""

    BTF_KIND_UNKN = 0
    BTF_KIND_INT = 1
    BTF_KIND_PTR = 2
    BTF_KIND_ARRAY = 3
    BTF_KIND_STRUCT = 4
    BTF_KIND_UNION = 5
    BTF_KIND_ENUM = 6
    BTF_KIND_FWD = 7
    BTF_KIND_TYPEDEF = 8
    BTF_KIND_VOLATILE = 9
    BTF_KIND_CONST = 10
    BTF_KIND_RESTRICT = 11
    BTF_KIND_FUNC = 12
    BTF_KIND_FUNC_PROTO = 13
    BTF_KIND_VAR = 14
    BTF_KIND_DATASEC = 15
    BTF_KIND_FLOAT = 16
    BTF_KIND_DECL_TAG = 17
    BTF_KIND_TYPE_TAG = 18
    BTF_KIND_ENUM64 = 19


class BtfException(Exception):
    """Raised when obtaining BTF is not possible"""


class Btf:
    def __init__(
        self,
        btf: interfaces.objects.ObjectInterface,
        context: interfaces.context.ContextInterface,
    ):
        self.btf = btf
        self.context = context
        if self.btf.has_valid_member("types"):
            self.types = array_of_pointers(
                self.btf.types.dereference(),
                self.btf.nr_types,
                make_vol_type("btf_type", self.context),
                self.context,
            )
        else:
            raise BtfException

    def get_string(self, type_id) -> str:
        btf_type = self._type_by_id(type_id)
        return self._get_string(btf_type.name_off)

    def sprintf_bytes(
        self,
        b: bytes,
        type_id: int,
        btf_type: Optional[interfaces.objects.ObjectInterface] = None,
    ) -> str:
        """Pretty print a bytes array using its BPF type information.
        inspired by "bpf_snprintf_btf" helper, "btf_type_show" in particular
        """
        s = ""
        if not btf_type:
            btf_type = self._type_by_id(type_id)
        kind_flag, kind, vlen = self._parse_info(int(btf_type.info))

        # check "btf_kind_operations" for implementation details
        if kind == BtfKind.BTF_KIND_DATASEC:
            # btf_datasec_show
            s += (
                f"section ({self._get_string(btf_type.name_off)}) = "
                + "{\n"
            )
            for vsi in self._list_vector(btf_type, kind, vlen):
                s += self.sprintf_bytes(
                    b[vsi.offset : vsi.offset + vsi.size], vsi.type
                )
        elif kind == BtfKind.BTF_KIND_VAR:
            # btf_var_show
            s += f" ({self._get_string(btf_type.name_off)})"
            type_id, btf_type = self._type_id_resolve(type_id)
            s += self.sprintf_bytes(b, type_id, btf_type=btf_type)
        elif kind == BtfKind.BTF_KIND_ARRAY:
            # stub, check btf_array_show
            s += " " + str(b) + "\n"
        elif kind == BtfKind.BTF_KIND_INT:
            # stub, check btf_int_show
            s += f" ({self._get_string(btf_type.name_off)})"
            s += " " + str(b) + "\n"
        else:
            vollog.log(
                constants.LOGLEVEL_V,
                f"BTF kind not (yet) supported: {kind}, defaulting to"
                " hex dump",
            )
            s += f"[{' '.join(map(lambda n: format(n, '02x'), list(b)))}]"
        return s

    def _type_id_resolve(
        self, type_id: int
    ) -> Tuple[int, interfaces.objects.ObjectInterface]:
        # btf_type_id_resolve
        type_id = self._resolved_type_id(type_id)
        return type_id, self._type_by_id(type_id)

    def _resolved_type_id(self, type_id: int) -> int:
        # btf_resolved_type_id
        btf = self.btf
        while type_id < btf.start_id:
            btf = btf.base_btf
        return btf.resolved_ids.dereference().cast(
            "array",
            count=0xFFFF,
            subtype=get_vol_template("unsigned int", self.context),
        )[type_id - btf.start_id]

    def _type_by_id(
        self, type_id: int
    ) -> interfaces.objects.ObjectInterface:
        # btf_type_by_id
        btf = self.btf
        while type_id < btf.start_id:
            btf = btf.base_btf
        return array_of_pointers(
            btf.types.dereference(),
            btf.nr_types,
            make_vol_type("btf_type", self.context),
            self.context,
        )[type_id - btf.start_id].dereference()

    def _get_string(self, offset: int) -> str:
        """Fetch a string from the string table"""
        return get_object(
            "char",
            self.btf.strings.dereference().vol.offset + offset,
            self.context,
        ).cast("string", max_length=100, errors="replace")

    def _parse_info(self, info: int) -> Tuple[bool, BtfKind, int]:
        """Parse the btf_type.info into (kind_flag, kind, vlen)"""
        kind_flag = bool(info & 2**31)
        kind = BtfKind((info >> 24) & 0b11111)
        vlen = info & (2**15 - 1)
        return kind_flag, kind, vlen

    def _list_vector(
        self,
        btf_type: interfaces.objects.ObjectInterface,
        kind: BtfKind,
        vlen: int,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """List the vector that succeeds some kinds of types"""
        start = btf_type.vol.offset + btf_type.vol.size
        elem_type = self._kind_to_vtype(kind)
        elem_sz = get_vol_template(elem_type, self.context).vol.size
        for i in range(0, vlen):
            obj = get_object(
                elem_type, start + elem_sz * i, self.context
            )
            yield obj

    def _kind_to_vtype(self, kind: BtfKind) -> Optional[str]:
        """Map a kind to the type of the data that follows it"""
        if kind == BtfKind.BTF_KIND_DATASEC:
            return "btf_var_secinfo"
        return None


class TraceEventType:
    """TODO: Can I get variants of unnamed enums from symbols?"""

    TRACE_EVENT_FL_FILTERED_BIT = 0
    TRACE_EVENT_FL_CAP_ANY_BIT = 1
    TRACE_EVENT_FL_NO_SET_FILTER_BIT = 2
    TRACE_EVENT_FL_IGNORE_ENABLE_BIT = 3
    TRACE_EVENT_FL_TRACEPOINT_BIT = 4
    TRACE_EVENT_FL_DYNAMIC_BIT = 5
    TRACE_EVENT_FL_KPROBE_BIT = 6
    TRACE_EVENT_FL_UPROBE_BIT = 7
    TRACE_EVENT_FL_EPROBE_BIT = 8
    TRACE_EVENT_FL_CUSTOM_BIT = 9


class TraceEventFlag(Flag):
    """TODO: Can I get variants of unnamed enums from symbols?"""

    TRACE_EVENT_FL_FILTERED = (
        1 << TraceEventType.TRACE_EVENT_FL_FILTERED_BIT
    )
    TRACE_EVENT_FL_CAP_ANY = (
        1 << TraceEventType.TRACE_EVENT_FL_CAP_ANY_BIT
    )
    TRACE_EVENT_FL_NO_SET_FILTER = (
        1 << TraceEventType.TRACE_EVENT_FL_NO_SET_FILTER_BIT
    )
    TRACE_EVENT_FL_IGNORE_ENABLE = (
        1 << TraceEventType.TRACE_EVENT_FL_IGNORE_ENABLE_BIT
    )
    TRACE_EVENT_FL_TRACEPOINT = (
        1 << TraceEventType.TRACE_EVENT_FL_TRACEPOINT_BIT
    )
    TRACE_EVENT_FL_DYNAMIC = (
        1 << TraceEventType.TRACE_EVENT_FL_DYNAMIC_BIT
    )
    TRACE_EVENT_FL_KPROBE = (
        1 << TraceEventType.TRACE_EVENT_FL_KPROBE_BIT
    )
    TRACE_EVENT_FL_UPROBE = (
        1 << TraceEventType.TRACE_EVENT_FL_UPROBE_BIT
    )
    TRACE_EVENT_FL_EPROBE = (
        1 << TraceEventType.TRACE_EVENT_FL_EPROBE_BIT
    )
    TRACE_EVENT_FL_CUSTOM = (
        1 << TraceEventType.TRACE_EVENT_FL_CUSTOM_BIT
    )


class BpfLink:
    def __init__(
        self,
        link: interfaces.objects.ObjectInterface,
        context: interfaces.context.ContextInterface,
    ):
        self.link = link
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
        is possible). TODO: hardcoding of types breaks backwards/
        forwards compatibility.
        """
        match self.type:
            case self.types.BPF_LINK_TYPE_ITER:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_iter_link",
                    "link",
                    self.context,
                )
            case self.types.BPF_LINK_TYPE_PERF_EVENT:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_perf_link",
                    "link",
                    self.context,
                )
            case self.types.BPF_LINK_TYPE_KPROBE_MULTI:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_kprobe_multi_link",
                    "link",
                    self.context,
                )
            case self.types.BPF_LINK_TYPE_RAW_TRACEPOINT:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_raw_tp_link",
                    "link",
                    self.context,
                )
            case self.types.BPF_LINK_TYPE_TRACING:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_tracing_link",
                    "link",
                    self.context,
                )
            case self.types.BPF_LINK_TYPE_CGROUP:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_cgroup_link",
                    "link",
                    self.context,
                )
            case self.types.BPF_LINK_TYPE_NETNS:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_netns_link",
                    "link",
                    self.context,
                )
            case self.types.BPF_LINK_TYPE_XDP:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_xdp_link",
                    "link",
                    self.context,
                )
            case self.types.BPF_LINK_TYPE_STRUCT_OPS:
                return container_of(
                    int(self.link.vol.offset),
                    "bpf_tramp_link",
                    "link",
                    self.context,
                )
            case _:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"Bug or kernel update.",
                )
                return None

    @property
    def attach_type(self):
        """Returns: The attach type of the link"""
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
                    f"Bug or kernel update.",
                )
        return self._attach_type

    @property
    def attach_to(self) -> str:
        match self.type:
            case self.types.BPF_LINK_TYPE_ITER:
                return f"iter/{pointer_to_string(self.typed_link.tinfo.reg_info.target, 9999)}"

            case self.types.BPF_LINK_TYPE_PERF_EVENT:
                s = ""
                match self.prog.type:
                    case self.prog.types.BPF_PROG_TYPE_KPROBE:
                        s += "kprobe/"
                    case self.prog.types.BPF_PROG_TYPE_PERF_EVENT:
                        s += "perf_event/"
                    case self.prog.types.BPF_PROG_TYPE_TRACEPOINT:
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
                    f"BPF link type not supported: {self.type}",
                )
                return ""


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
                    f"Kernel version before v5.0-rc1 does not support"
                    "prog BTF",
                )
                raise BtfException
            # BTF is nice-to-have, but a program is not required to
            # have it
            elif int(self.aux.btf) == 0:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"Program does not have BTF info attached",
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
    def symbol_table(self) -> Dict[int, str]:
        if self._symbol_table:
            return self._symbol_table
        ret = dict()
        # add all functions, including "main"
        for func in chain([self], self.funcs):
            ret.update({int(func.prog.bpf_func): func.name})
        # all calls to kernel functions
        for i in chain(
            self.mdisasm, *(func.mdisasm for func in self.funcs)
        ):
            if i.insn_name() == "call":
                # check if we already resolved the address
                if ret.get(int(i.op_str, 16), None):
                    continue
                try:  # to resolve helper by mapping address->symbol
                    ret.update(
                        {
                            int(
                                i.op_str, 16
                            ): self.vmlinux.get_symbols_by_absolute_location(
                                int(i.op_str, 16)
                            )[
                                0
                            ].split(
                                constants.BANG
                            )[
                                1
                            ]
                        }
                    )
                except Exception as E:
                    # Probably call to a function within the BPF
                    # program itself. TODO: Follow control flow.
                    vollog.log(
                        constants.LOGLEVEL_V,
                        f"Unable to resolve address of call {i} ({E})",
                    )

        self._symbol_table = ret
        return self._symbol_table

    @property
    def funcs(self) -> List[BpfProg]:
        """A 'main' BPF program may call functions that are also
        implemented im BPF, i.e. BPF2BPF calls. This returns the list
        of all 'such function programs'"""
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
            self._funcs = [
                BpfProg(prog, self.context) for prog in func_ptrs
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
            ns_since_boot2datetime(int(self.aux.load_time)),
            ",".join(self.helpers),
            ",".join([str(m.map.id) for m in self.maps]),
            str(self.link.type) if self.link else "n.a.",
            str(self.attach_type) if self.attach_type else "n.a.",
            self.attach_to,
        )

    @property
    def attach_to(self):
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
        ret = []
        for i in chain(
            self.mdisasm, *(func.mdisasm for func in self.funcs)
        ):
            # annotate above the line, e.g. the beginning of functions
            label = self.symbol_table.get(i.address, None)
            if label:
                ret.append(f"\n{label}:")
            # annotate at the end of the line
            end = ""
            if i.insn_name() == "call":
                end = "\t# " + self.symbol_table.get(
                    int(i.op_str, 16), ""
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
        TODO: Can multiple links reference the same prog?"""
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
        if self.aux.used_map_cnt > 0:
            map_ptrs = array_of_pointers(
                self.aux.used_maps.dereference(),
                self.aux.used_map_cnt,
                make_vol_type("bpf_map", self.context),
                self.context,
            )
            return [BpfMap(m, self.context) for m in map_ptrs]
        else:
            return []

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
        ret = set(self.symbol_table.values())
        ret.remove(self.name)
        return ret


class BpfMap:
    def __init__(
        self,
        m: interfaces.objects.ObjectInterface,
        context: interfaces.context.ContextInterface,
    ):
        self.map = (
            m
            if m.vol.type_name == make_vol_type("bpf_map", context)
            else m.dereference().cast("bpf_map")
        )
        self.context = context
        self.vmlinux = self.context.modules["kernel"]
        self.types = Enum(
            "BpfMapType",
            names=self.vmlinux.get_enumeration(
                "bpf_map_type"
            ).choices.items(),
        )

        try:
            # BTF for maps was introduced in a26ca7c, v4.18-rc1
            if not self.map.has_valid_member("btf"):
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"Kernel version before v4.18-rc1 does not support"
                    "map BTF",
                )
                raise BtfException
            # BTF is nice-to-have, but a map is not required to
            # have it
            elif int(self.map.btf) == 0:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"Map does not have BTF info attached",
                )
                raise BtfException
            else:
                self.btf = Btf(self.map.btf, context)
        except BtfException:
            self.btf = None

        self.type = self.types(self.map.map_type)
        self.vmlinux_btf = None
        self.btf_key_type_id = int(self.map.btf_key_type_id)
        self.btf_value_type_id = int(self.map.btf_value_type_id)
        # struct ops maps were introduced in 85d33df, v5.6-rc1
        self.btf_vmlinux_value_type_id = (
            int(self.map.btf_vmlinux_value_type_id)
            if self.map.has_valid_member("btf_vmlinux_value_type_id")
            else None
        )
        self.name = str(array_to_string(self.map.name))

    def row(self):
        """Extract the fields needed for the final output.
        Args:
            dump: If True, full map contents are included in the output.
        Returns:
            A tuple with the fields to show in the plugin output.
        """

        return (
            hex(self.map.vol.offset),
            int(self.map.id),
            self.name,
            str(self.type),
            int(self.map.key_size),
            int(self.map.value_size),
            int(self.map.max_entries),
        )

    def items(self) -> Iterable[Tuple[Any, Any]]:
        """Iterate over the map.
        Returns:
            Iterator holding (key, value) pairs stored in the map.
        """
        if self.type == self.types.BPF_MAP_TYPE_ARRAY:
            return self._gen_array()
        else:
            vollog.log(
                constants.LOGLEVEL_V,
                f"BPF map type not (yet) supported: {self.type}",
            )
            return []

    def dump(self) -> str:
        """Dump the map's content as a string."""
        ret = dict()
        for k, v in self.items():
            if self.btf_key_type_id:
                k = self.btf.sprintf_bytes(k, self.btf_key_type_id)
            else:
                k = str(k)

            if self.btf_value_type_id:
                v = self.btf.sprintf_bytes(v, self.btf_value_type_id)
            elif self.btf_vmlinux_value_type_id:
                v = self.vmlinux_btf.sprintf_bytes(
                    v, self.btf_vmlinux_value_type_id
                )
            else:
                v = str(v)

            ret.update({k: v})

        return dumps(ret)

    def _gen_array(self):
        array = container_of(
            int(self.map.vol.offset), "bpf_array", "map", self.context
        )

        for i in range(0, int(self.map.max_entries)):
            data_ptr = int(array.value.vol.offset) + (
                i & int(array.index_mask)
            ) * int(array.elem_size)
            data = self.context.layers.read(
                self.vmlinux.layer_name, data_ptr, int(array.elem_size)
            )
            yield (i, data)


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
                f"Kernel version has no BPF links",
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
                f"Kernel version not (yet) supported",
            )
            return []

        xarray = XArray(link_idr.idr_rt, "bpf_link", context)

        for link in xarray.xa_for_each():
            if filter_func(link):
                continue
            yield BpfLink(link, context)
