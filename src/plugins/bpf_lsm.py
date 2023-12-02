# SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>
# SPDX-License-Identifier: MIT

"""
Volatility3 plugin that shows the current state of the Kernel Runtime
Security Instrumentation (KRSI) framework.
"""
import logging
from collections.abc import Iterable
from itertools import takewhile
from typing import Optional

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsError

from volatility3.framework.interfaces.context import (
    ContextInterface,
    ModuleInterface,
)
from volatility3.framework.renderers import TreeGrid
from volatility3.framework import constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.exceptions import PagedInvalidAddressException
from volatility3.utility.prog import BpfProg
from volatility3.utility.link import BpfLink
from volatility3.plugins.linux.bpf_listlinks import LinkList
from volatility3.framework.interfaces.symbols import SymbolInterface

vollog = logging.getLogger(__name__)


class BpfLsm(interfaces.plugins.PluginInterface):
    """Volatility3 plugin that shows the current state of the Kernel
    Runtime Security Instrumentation (KRSI) framework."""

    _required_framework_version = (2, 0, 0)

    _version = (0, 0, 0)

    @classmethod
    def get_requirements(
        cls,
    ) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="bpf_listlinks",
                plugin=LinkList,
                version=(0, 0, 0),
            ),
        ]

    @staticmethod
    def _get_tramp_address(
        hook: interfaces.symbols.SymbolInterface,
        hook_address: int,
        raw: bytes,
    ) -> Optional[int]:
        """If there is a BPF trampoline attached to the hook, returns
        its address."""
        # TODO: Disassembling sometimes fails. How can I know the size
        # of those stubs in advance?
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            mdisasm = list(
                takewhile(
                    lambda insn: insn.mnemonic != "ret",
                    md.disasm(raw, hook_address),
                )
            )
        except CsError as E:
            vollog.warning(
                "Unable to disassemble trivial BPF LSM stub "
                f"{hook.name} ({E})",
            )
            return None
        # The first (and hopefully only) call instruction (if present)
        # in the bpf_lsm_ stub will give us the address of the BPF
        # trampoline.
        tramp_address_str: str | None = next(
            (insn.op_str for insn in mdisasm if insn.mnemonic == "call"),
            None,
        )
        if tramp_address_str is not None:
            tramp_address: int = int(tramp_address_str, 16)
            vollog.info(
                f"Found call to trampoline at {hex(tramp_address)}, "
                f"{[' '.join([insn.mnemonic, insn.op_str]) for insn in mdisasm]}"
            )
            return tramp_address

    @classmethod
    def list_bpf_lsm(
        cls,
        context: ContextInterface,
        symbol_table: str,
    ) -> Iterable[tuple[SymbolInterface, list[BpfProg]]]:
        """Generates all the LSM hooks that have at least one BPF
        program attached"""
        vmlinux: ModuleInterface = context.modules[symbol_table]

        # Only tracing links can attach to the LSM hooks (true?)
        tr_links: list[BpfLink] = list(
            lnk
            for lnk in LinkList.list_links(
                context,
                symbol_table,
                lambda link: not str(link.type).endswith("TYPE_TRACING"),
            )
        )
        vollog.info(
            f"Found {len(tr_links)} tracing links"
            f"trampolines {[hex(link._downcast('bpf_tracing_link').trampoline.cur_image.image) for link in tr_links]}"
        )
        kvo: int = int(
            context.layers[vmlinux.layer_name].config["kernel_virtual_offset"]
        )
        for hook in (
            vmlinux.get_symbol(sym)
            for sym in vmlinux.symbols
            if sym.startswith("bpf_lsm_")
        ):
            # account for virtual KASLR
            hook_address: int = int(hook.address) + kvo
            try:
                mcode: bytes = context.layers.read(
                    vmlinux.layer_name,
                    hook_address,
                    32,
                )
                tramp_address: int | None = cls._get_tramp_address(
                    hook,
                    hook_address,
                    mcode,
                )
            except PagedInvalidAddressException as E:
                # TODO: This should not happen... Figure out why it does
                # happen sometimes!
                vollog.warning(
                    "Unable to read instructions of trivial BPF LSM "
                    f"stub {hook.name} at {hex(hook_address)} ({E})",
                )
                continue
            if not tramp_address:
                # There is no BPF program on this hook.
                continue
            vollog.info(
                f"Hook {hook.name}@{hex(hook_address)} is attached to trampoline@{hex(tramp_address)}"
            )
            # Find the link(s) that attach program(s) to this hook.
            prog_list: list[BpfProg] = [
                BpfProg(link.prog, context)
                for link in tr_links
                if link._downcast("bpf_tracing_link").trampoline.cur_image.image
                == tramp_address
            ]
            if not prog_list:
                # This could indicate hidden BPF objects, a currupt
                # memory image or an ordinary bug in my code.
                vollog.warning(
                    "Unable to find a link for in-use BPF LSM hook "
                    f"{hook.name}",
                )
                continue
            yield hook, prog_list

    def _generator(
        self,
    ) -> Iterable[tuple[int, tuple]]:
        """Generates the rows of the output."""
        symbol_table: str = str(self.config["kernel"])

        for hook, prog_list in self.list_bpf_lsm(self.context, symbol_table):
            yield (
                0,
                (
                    hook.name,
                    len(prog_list),
                    ",".join(str(prog.aux.id) for prog in prog_list),
                ),
            )

    def run(self) -> TreeGrid:
        columns: list[tuple[str, type]] = [
            ("LSM HOOK", str),
            ("Nr. PROGS", int),
            ("IDs", str),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )
