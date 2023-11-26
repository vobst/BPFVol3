"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT

This file contains small helper functions that are used in more than
one other part of the code.
"""
import logging

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
