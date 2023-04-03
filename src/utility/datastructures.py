"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT

This file contains classes for parsing Linux data structures
"""
import logging
from typing import (
    Iterable,
    Optional,
)

from volatility3.framework import constants
from volatility3.framework import interfaces
from volatility3.utility.helpers import get_object

vollog = logging.getLogger(__name__)


class XArray:
    """Oversimplified and incomplete iterator for XArrays of pointers"""

    XA_CHUNK_SHIFT = 6  # correct if CONFIG_BASE_SMALL = 0
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
        """Returns:
        Node or pointer entry for current offset and node,
        else None. Never returns 0.
        """
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

        while not entry:
            entry = self.xas_get_entry_from_offset()
            if not entry:
                self.xas_offset += 1
                while not self.xas_offset_valid():
                    self.xas_offset = self.xas_node.offset + 1
                    self.xas_node = (
                        self.xas_node.parent.dereference().cast(
                            "xa_node"
                        )
                    )
                if not self.xas_node_valid():
                    entry = None
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
                entry = None
                break

        return entry