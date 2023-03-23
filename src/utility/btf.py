"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT

This file contains classes for working with BPF type information.
"""
import logging
from typing import (
    Iterable,
    Optional,
    Tuple,
)
from enum import Enum

from volatility3.framework import constants
from volatility3.framework.objects.utility import array_of_pointers
from volatility3.framework import interfaces

from volatility3.utility.helpers import (
    make_vol_type,
    get_vol_template,
    get_object,
)
from volatility3.utility.enums import BtfKind

vollog = logging.getLogger(__name__)


class BtfException(Exception):
    """Raised when obtaining BTF is not possible"""

    pass


class Btf:
    """Wraps a struct btf and implements, e.g., pretty printing of data
    by using type information."""

    # Map a kind to the type of the data that follows it
    kind_to_vtype = {BtfKind.BTF_KIND_DATASEC: "btf_var_secinfo"}

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
        elem_type = self.kind_to_vtype.get(kind, None)
        if not elem_type:
            vollog.log(
                constants.LOGLEVEL_V,
                "Listing of vector for BTF kind not (yet) supported: "
                f"{kind}",
            )
            return []
        elem_sz = get_vol_template(elem_type, self.context).vol.size
        for i in range(0, vlen):
            obj = get_object(
                elem_type, start + elem_sz * i, self.context
            )
            yield obj
