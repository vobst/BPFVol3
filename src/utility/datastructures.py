# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""This module contains classes for parsing Linux data structures"""
import logging
from collections.abc import Iterable
from typing import Optional

from volatility3.framework import constants, interfaces
from volatility3.utility.helpers import get_object

vollog = logging.getLogger(__name__)

XA_SPECIAL_ENTRY_THRESHOLD: int = 0x1000


class XArray:
    """Simple iterator for XArrays of pointers"""

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
        # Node we are currently visiting
        self.xas_node = self.xa_to_node(int(self.xarray.xa_head))
        # Offset into the node's slots that we are currently working at
        self.xas_offset = 0

    def _construct_subtype_obj(
        self, entry: int
    ) -> interfaces.objects.ObjectInterface:
        return get_object(self.subtype, entry, self.context)

    def xa_is_node(self, entry: int) -> bool:
        """Tests if an entry is a pointer to another node"""
        return self.xa_is_internal(entry) and entry > XA_SPECIAL_ENTRY_THRESHOLD

    def xa_is_internal(self, entry: int) -> bool:
        """
        Test if an entry belongs to the xarray implementation, i.e., is not a
        value entry belonging to the user.
        """
        return (entry & 0b11) == 0b10  # noqa: PLR2004

    def xa_to_node(self, entry: int) -> interfaces.objects.ObjectInterface:
        """Converts an entry pointing to another node to the actual pointer"""
        return get_object("xa_node", entry - 0b10, self.context)

    def xa_is_pointer(self, entry: int) -> bool:
        """Test if an entry is a value entry belonging to the user"""
        return (entry & 0b11) == 0b00 and entry != 0

    def xas_valid(self) -> bool:
        """Test if the current iteration state is valid"""
        if self.xas_offset_valid() and self.xas_node_valid():
            return True
        return False

    def xas_offset_valid(self) -> bool:
        """Test if the current slot offset is valid"""
        if self.xas_offset in range(self.XA_CHUNK_SIZE):
            return True
        return False

    def xas_node_valid(self) -> bool:
        """Check if the current node is valid"""
        if not isinstance(self.xas_node, interfaces.objects.ObjectInterface):
            return False
        if self.xas_node.vol.type_name.split(constants.BANG)[1] != "xa_node":
            return False
        if int(self.xas_node.vol.offset) == 0:
            return False
        return True

    def xas_get_entry_from_offset(self) -> Optional[int]:
        """
        Returns:
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
        # xarrays with a single entry do not have any nodes, the pointer to the
        # first node is actually the entry
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
        """Returns:
        The next entry, or None if there are no more entries. Advances the
        internal iteration state.
        """
        entry = None

        while not entry:
            entry = self.xas_get_entry_from_offset()
            if not entry:
                self.xas_offset += 1  # shift
                while not self.xas_offset_valid():  # ascend
                    self.xas_offset = self.xas_node.offset + 1
                    self.xas_node = self.xas_node.parent.dereference().cast(
                        "xa_node"
                    )
                if not self.xas_node_valid():
                    entry = None
                    break
                continue
            if self.xa_is_node(entry):  # descend
                self.xas_node = self.xa_to_node(entry)
                self.xas_offset = 0
                entry = None
                continue
            if self.xa_is_pointer(entry):  # got entry, yield it
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
