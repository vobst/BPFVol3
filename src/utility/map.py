"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT

This file contains functionality to display general information
about BPF maps and to dump their contents
"""
import logging
from typing import (
    Iterable,
    Tuple,
    Any,
)
from json import dumps
from enum import Enum

from volatility3.framework import constants
from volatility3.framework.objects.utility import array_to_string
from volatility3.framework import interfaces

from volatility3.utility.btf import Btf, BtfException
from volatility3.utility.helpers import make_vol_type, container_of

vollog = logging.getLogger(__name__)


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
                    "Kernel version before v4.18-rc1 does not support"
                    "map BTF",
                )
                raise BtfException
            # BTF is nice-to-have, but a map is not required to
            # have it
            elif int(self.map.btf) == 0:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Map does not have BTF info attached",
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
            if self.btf_key_type_id and self.btf:
                k = self.btf.sprintf_bytes(k, self.btf_key_type_id)
            else:
                k = str(k)

            if self.btf_value_type_id and self.btf:
                v = self.btf.sprintf_bytes(v, self.btf_value_type_id)
            elif self.btf_vmlinux_value_type_id and self.vmlinux_btf:
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
        if not array:
            vollog.log(
                constants.LOGLEVEL_V,
                f"Bug",
            )
            return []

        for i in range(0, int(self.map.max_entries)):
            data_ptr = int(array.value.vol.offset) + (
                i & int(array.index_mask)
            ) * int(array.elem_size)
            data = self.context.layers.read(
                self.vmlinux.layer_name, data_ptr, int(array.elem_size)
            )
            yield (i, data)
