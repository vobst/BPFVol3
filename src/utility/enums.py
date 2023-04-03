from enum import Flag, Enum


class BtfKind(Enum):
    """Anonymous enum defined in /include/uapi/linux/btf.h"""

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


class TraceEventType:
    """Anonymous enum defined in /include/linux/trace_events.h"""

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
    """Anonymous enum defined in /include/linux/trace_events.h"""

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