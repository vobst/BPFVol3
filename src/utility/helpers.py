"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT

This file contains small helper functions that are used in more than
one other part of the code.
"""
import logging
from typing import Optional

from volatility3.framework import constants, interfaces

vollog = logging.getLogger(__name__)


def make_vol_type(
    type_name: str,
    context: interfaces.context.ContextInterface,
) -> str:
    """Prepend symbol table name to type name."""
    vmlinux = context.modules["kernel"]
    return str(vmlinux.symbol_table_name + constants.BANG + type_name)


def get_vol_template(
    type_name: str,
    context: interfaces.context.ContextInterface,
) -> interfaces.objects.Template:
    """Get the template for a type name."""
    vmlinux = context.modules["kernel"]
    return vmlinux.get_type(make_vol_type(type_name, context))


def get_object(
    type_name: str,
    offset: int,
    context: interfaces.context.ContextInterface,
) -> interfaces.objects.ObjectInterface:
    """Construct object from type name and offset."""
    vmlinux = context.modules["kernel"]
    return vmlinux.object(type_name, offset, absolute=True)


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
