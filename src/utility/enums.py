from enum import Enum


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
