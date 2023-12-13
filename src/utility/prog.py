# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
This module contains functionality to display general information
about BPF programs and to dump their code
"""
from __future__ import annotations

import logging
import re
from enum import Enum
from itertools import chain
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterable

from capstone import (
    CS_ARCH_BPF,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_MODE_BPF_EXTENDED,
    Cs,
    CsError,
    CsInsn,
)

from volatility3.framework import constants
from volatility3.framework.objects.utility import (
    array_of_pointers,
    array_to_string,
)
from volatility3.utility.btf import Btf, BtfError
from volatility3.utility.helpers import get_vol_template, make_vol_type
from volatility3.utility.map import BpfMap

if TYPE_CHECKING:
    from volatility3.framework.interfaces.context import (
        ContextInterface,
        ModuleInterface,
    )
    from volatility3.framework.interfaces.objects import ObjectInterface

vollog: logging.Logger = logging.getLogger(__name__)


# the different kinds of symbols that might appear in a BPF program
class BpfProgSymKind(Enum):
    MAIN = 1  # the program itself
    FUNC = 2  # subprograms called by the main program
    HELPER = 3  # bpf helpers and kfuncs
    MAP = 4  # maps
    # TODO: other kinds of kernel symbols


# represents a symbol that is referenced within a BPF program
class BpfProgSym(NamedTuple):
    name: str
    kind: BpfProgSymKind


class BpfProg:
    def __init__(
        self,
        prog: ObjectInterface,
        context: ContextInterface,
    ) -> None:
        self.prog: ObjectInterface = (
            prog
            if prog.vol.type_name == make_vol_type("bpf_prog", context)
            else prog.dereference().cast("bpf_prog")
        )
        self.context: ContextInterface = context
        self.vmlinux: ModuleInterface = self.context.modules["kernel"]
        self.types = Enum(
            "BpfProgType",
            names=self.vmlinux.get_enumeration("bpf_prog_type").choices.items(),
        )

        self.aux: ObjectInterface = self.prog.aux
        self.type = self.types(self.prog.type)

        try:
            # btf info for programs was introduced in 838e969, v5.0-rc1
            if not self.aux.has_valid_member("btf"):
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Kernel version before v5.0-rc1 does not support prog BTF",
                )
                raise BtfError
            # BTF is nice-to-have, but a program is not required to have it
            if int(self.aux.btf) == 0:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Program does not have BTF info attached",
                )
                raise BtfError

            # ok, we have btf info
            self.btf: Btf | None = Btf(self.aux.btf, context)
        except BtfError:
            self.btf: Btf | None = None

        # lazy init
        self._link = None
        self._attach_type = None
        self._attach_to = None
        self._net_dev = None
        self._mcode: bytes | None = None
        self._mdisasm: list[CsInsn] | None = None
        self._bcode: bytes | None = None
        self._bdisasm: list[CsInsn] | None = None
        self._funcs: list[BpfProg] | None = None
        self._symbol_table: dict[int, BpfProgSym] | None = None
        self._name: str | None = None
        self._maps: list[BpfMap] | None = None

    def __eq__(self, other: BpfProg) -> bool:
        return self.prog.vol.get("offset") == other.prog.vol.get("offset")

    @property
    def label(self) -> str:
        return f"{self.aux.id}/{self.name}"

    @property
    def name(self) -> str:
        if self._name:
            return self._name

        if self.aux.has_valid_member("func_info") and self.btf:
            func_info = self.aux.func_info.dereference().cast(
                "array",
                count=(1 if self.aux.func_cnt == 0 else self.aux.func_cnt),
                subtype=get_vol_template("bpf_func_info", self.context),
            )
            self._name = self.btf.get_string(
                func_info[self.aux.func_idx].type_id
            )
        else:
            self._name = str(array_to_string(self.aux.name))

        return self._name

    @property
    def funcs(self) -> list[BpfProg]:
        """
        A 'main' BPF program may call functions that are also
        implemented im BPF, i.e. BPF2BPF calls. This returns the list
        of all such 'function programs', aka. subprograms
        """
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
            # the first entry is the main program itself, which we do
            # not want to include here
            self._funcs = [
                BpfProg(prog, self.context) for prog in func_ptrs[1:]
            ]
        else:
            self._funcs = []

        return self._funcs

    @property
    def maps(self) -> list[BpfMap]:
        """Returns:
        Maps used by the program."""
        if self._maps:
            return self._maps

        if self.aux.used_map_cnt > 0:
            map_ptrs = array_of_pointers(
                self.aux.used_maps.dereference(),
                self.aux.used_map_cnt,
                make_vol_type("bpf_map", self.context),
                self.context,
            )
            self._maps = [BpfMap(m, self.context) for m in map_ptrs]
        else:
            self._maps = []

        return self._maps

    @property
    def mcode(self) -> bytes:
        """
        Returns:
            Machine code of the program
        """
        if self._mcode:
            return self._mcode

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

        vollog.log(
            constants.LOGLEVEL_V,
            f"Number of bytecode instructions: {self.prog.len}",
        )

        self._bcode = bytes(
            self.context.layers.read(
                self.vmlinux.layer_name,
                self.prog.insnsi.vol.get("offset"),
                self.prog.len * 8,  # sizeof(struct bpf_insn)
            )
        )

        vollog.log(
            constants.LOGLEVEL_V,
            f"Read bytecode length: {len(self._bcode)}",
        )

        return self._bcode

    @property
    def mdisasm(self) -> list[CsInsn]:
        if self._mdisasm:
            return self._mdisasm

        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._mdisasm = list(md.disasm(self.mcode, int(self.prog.bpf_func)))
        except CsError as E:
            vollog.log(
                constants.LOGLEVEL_V,
                f"Unable to disassemble jited program id={self.aux.id} ({E})",
            )
            self._mdisasm = []

        return self._mdisasm

    @property
    def bdisasm(self) -> Iterable[Any]:
        # note: there is a known issue in Capstone that BPF is not disassembled
        # correctly
        if self._bdisasm:
            return self._bdisasm

        try:
            md = Cs(CS_ARCH_BPF, CS_MODE_BPF_EXTENDED)
            self._bdisasm = list(md.disasm(self.bcode, 0))
        except CsError as E:
            vollog.log(
                constants.LOGLEVEL_V,
                f"Unable to disassemble bytecode of program id={self.aux.id} "
                f"({E})",
            )
            self._bdisasm = []

        vollog.log(
            constants.LOGLEVEL_V,
            f"Number of disassembled instructions: {len(self._bdisasm)}",
        )

        return self._bdisasm

    @property
    def symbol_table(self) -> dict[int, BpfProgSym]:
        if self._symbol_table:
            return self._symbol_table

        symtab: dict[int, BpfProgSym] = {}
        # add the main program
        symtab.update(
            {
                int(self.prog.bpf_func): BpfProgSym(
                    self.name, BpfProgSymKind.MAIN
                )
            }
        )
        # add all functions, aka. subprograms
        for func in self.funcs:
            symtab.update(
                {
                    int(func.prog.bpf_func): BpfProgSym(
                        func.name, BpfProgSymKind.FUNC
                    )
                }
            )
        # add all maps (accesses to array maps may be jited to direct
        # memory loads and stores, i.e., they are not performed
        # through an accesor function that accepts a pointer to
        # the bpf_map object)
        for m in self.maps:
            symtab.update(
                {
                    int(m.map.vol.get("offset"))
                    + 0xFFFF000000000000: BpfProgSym(m.name, BpfProgSymKind.MAP)
                }
            )
        # all calls to kernel functions
        for i in chain(self.mdisasm, *(func.mdisasm for func in self.funcs)):
            if i.insn_name() == "call":
                # check if we already have a symbol for the address
                if symtab.get(int(i.op_str, 16), None):
                    continue
                try:  # to resolve helper by mapping address->symbol
                    symtab.update(
                        {
                            int(i.op_str, 16): BpfProgSym(
                                self.vmlinux.get_symbols_by_absolute_location(
                                    int(i.op_str, 16)
                                )[0].split(constants.BANG)[1],
                                BpfProgSymKind.HELPER,
                            )
                        }
                    )
                except Exception as E:
                    # there should always be a symbol as bpf2bpf calls
                    # are already resolved
                    vollog.info(
                        constants.LOGLEVEL_V,
                        f"BUG: Unable to resolve address of call {i} ({E})",
                    )

        self._symbol_table = symtab

        return self._symbol_table

    def get_symbol(self, address: int) -> tuple[BpfProgSym, int] | None:
        """
        Returns:
            The closest preceeding symbol in the program (within somewhat
            arbitrary bounds, to balance false positives and false
            negatives) along with its distance from the given address.
        """
        max_dist: int = 4096
        current: tuple[BpfProgSym, int] = (None, max_dist + 1)
        for saddr, symbol in self.symbol_table.items():
            dist: int = address - saddr
            if dist < 0:
                continue
            if dist == 0:
                return (symbol, 0)
            if dist < current[1]:
                current = (symbol, dist)

        return current if current[0] is not None else None

    def dump_mcode(self) -> str:
        # TODO: re-implement using Capstone's 'detailed' disassembly
        re_imm = re.compile(r"^.*?(0xffff[0-9a-f]+?)$")
        dump: list[str] = []

        for i in chain(self.mdisasm, *(func.mdisasm for func in self.funcs)):
            # if the instruction address is a symbol by itself, annotate above
            # the line, e.g. the beginning of functions
            symbol = self.symbol_table.get(i.address, None)
            if symbol:
                dump.append(f"\n{symbol.name}:")

            # annotate at the end of the line
            end = ""
            imm = re.search(re_imm, i.op_str)
            if imm:
                sym_off = self.get_symbol(int(imm.group(1), 16))
                if sym_off:
                    end = f"\t# {sym_off[0].name}" + (
                        f" + {hex(sym_off[1])}" if sym_off[1] else ""
                    )

            dump.append(
                f" {hex(i.address)}: "
                f"{' '.join([format(n, '02x') for n in list(i.bytes)])}"
                + (15 - i.size) * "   "
                + f" {i.mnemonic} "
                f"{i.op_str}"
                f"{end}"
            )

        return "\n".join(dump)

    def dump_bcode(self) -> str:
        dump = []
        for i in self.bdisasm:
            dump.append(
                f"{hex(i.address)}: "
                f"{' '.join([format(n, '02x') for n in list(i.bytes)])}"
                + (16 - i.size) * "   "
                + f" {i.mnemonic} "
                f"{i.op_str}"
            )
        return "\n".join(dump)

    @property
    def helpers(self) -> set[str]:
        """
        Returns:
            Set of all BPF helper, kfunc and BPF2BPF calls that happen in
            the program
        """
        return {
            symbol.name
            for symbol in self.symbol_table.values()
            if symbol.kind == BpfProgSymKind.HELPER
        }

    def row(self):
        """
        Returns:
            The plugin output for this particular program.
        """
        return (
            hex(self.prog.vol.offset),
            int(self.aux.id),
            str(self.type).removeprefix("BpfProgType.BPF_PROG_TYPE_"),
            self.name,
            "".join([format(x, "02x") for x in self.prog.tag]),
            int(self.aux.load_time),
            ",".join([str(m.map.id) for m in self.maps]),
            self.btf.btf.id if self.btf else -1,
            ",".join(self.helpers),
        )
