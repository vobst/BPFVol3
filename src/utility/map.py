# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
This file contains functionality to display general information
about BPF maps and to dump their contents
"""
import logging
from collections.abc import Iterable
from enum import Enum
from json import dumps

from volatility3.framework import constants
from volatility3.framework.interfaces.context import (
    ContextInterface,
    ModuleInterface,
)
from volatility3.framework.interfaces.objects import ObjectInterface
from volatility3.framework.objects.utility import array_to_string
from volatility3.framework.symbols.linux import LinuxUtilities
from volatility3.utility.btf import Btf, BtfException
from volatility3.utility.helpers import make_vol_type

vollog: logging.Logger = logging.getLogger(__name__)


class BpfMap:
    def __init__(
        self,
        m: ObjectInterface,
        context: ContextInterface,
    ) -> None:
        self.map: ObjectInterface = (
            m
            if m.vol.type_name == make_vol_type("bpf_map", context)
            else m.dereference().cast("bpf_map")
        )
        self.context: ContextInterface = context
        self.vmlinux: ModuleInterface = self.context.modules["kernel"]
        self.types = Enum(
            "BpfMapType",
            names=self.vmlinux.get_enumeration("bpf_map_type").choices.items(),
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

            # BTF is nice-to-have, but a map is not required to have it
            if int(self.map.btf) == 0:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Map does not have BTF info attached",
                )
                raise BtfException

            self.btf: Btf | None = Btf(self.map.btf, context)
        except BtfException:
            self.btf: Btf | None = None

        self.type = self.types(self.map.map_type)
        self.vmlinux_btf: Btf | None = None
        self.btf_key_type_id: int = int(self.map.btf_key_type_id)
        self.btf_value_type_id: int = int(self.map.btf_value_type_id)
        # struct ops maps were introduced in 85d33df, v5.6-rc1
        # https://lwn.net/Articles/811631/
        self.btf_vmlinux_value_type_id: int | None = (
            int(self.map.btf_vmlinux_value_type_id)
            if self.map.has_valid_member("btf_vmlinux_value_type_id")
            else None
        )
        self.name: str = str(array_to_string(self.map.name))

    @property
    def label(self) -> str:
        return f"{self.map.id}/{self.name}"

    def row(self):
        """Extract the fields needed for the final output
        Args:
            dump: If True, full map contents are included in the output
        Returns:
            A tuple with the fields to show in the plugin output
        """

        return (
            hex(self.map.vol.offset),
            int(self.map.id),
            str(self.type).removeprefix("BpfMapType.BPF_MAP_TYPE_"),
            self.name,
            int(self.map.key_size),
            int(self.map.value_size),
            int(self.map.max_entries),
        )

    def items(self) -> Iterable[tuple[bytes | int, bytes]]:
        """Iterate over the map
        Returns:
            Iterator holding (key, value) pairs stored in the map
        """
        if self.type == self.types.BPF_MAP_TYPE_ARRAY:
            return self._gen_array()

        vollog.log(
            constants.LOGLEVEL_V,
            f"BPF map type not (yet) supported: {self.type}",
        )
        return []

    def dump(self) -> str:
        """Dump the map's content as a string"""
        ret: dict[str, str] = {}
        for k, v in self.items():
            if self.btf_key_type_id and self.btf:
                k_repr: str = self.btf.sprintf_bytes(k, self.btf_key_type_id)
            else:
                k_repr: str = str(k)

            if self.btf_value_type_id and self.btf:
                v_repr: str = self.btf.sprintf_bytes(v, self.btf_value_type_id)
            elif self.btf_vmlinux_value_type_id and self.vmlinux_btf:
                v_repr: str = self.vmlinux_btf.sprintf_bytes(
                    v, self.btf_vmlinux_value_type_id
                )
            else:
                v_repr: str = str(v)

            ret.update({k_repr: v_repr})

        return dumps(ret)

    def _gen_array(self) -> Iterable[tuple[int, bytes]]:
        """Interprets the map as an array and yields index-value pairs"""
        array: ObjectInterface | None = LinuxUtilities.container_of(
            int(self.map.vol.offset), "bpf_array", "map", self.vmlinux
        )
        if not array:
            vollog.log(
                constants.LOGLEVEL_V,
                "Bug",
            )
            return []

        for i in range(int(self.map.max_entries)):
            data_ptr: int = int(array.value.vol.offset) + (
                i & int(array.index_mask)
            ) * int(array.elem_size)
            data: bytes = self.context.layers.read(
                self.vmlinux.layer_name, data_ptr, int(array.elem_size)
            )
            yield (i, data)
