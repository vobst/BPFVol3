"""
SPDX-FileCopyrightText: © 2023 Valentin Obst <legal@bpfvol3.de>

SPDX-License-Identifier: MIT

Volatility3 plugin that shows the current state of the Kernel Runtime
Security Instrumentation (KRSI) framework.
"""
import logging
from typing import Iterable, Tuple, List, Optional
from itertools import takewhile
from capstone import (
    Cs,
    CsError,
    CS_MODE_64,
    CS_ARCH_X86,
)

from volatility3.framework import interfaces, constants, renderers
from volatility3.framework.exceptions import (
    PagedInvalidAddressException,
)
from volatility3.framework.configuration import requirements

from volatility3.utility.prog import BpfProg, LinkList, BpfLink

vollog = logging.getLogger(__name__)


class BpfLsm(interfaces.plugins.PluginInterface):
    """Volatility3 plugin that shows the current state of the Kernel
    Runtime Security Instrumentation (KRSI) framework."""

    _required_framework_version = (2, 0, 0)

    _version = (0, 0, 0)

    columns = [
        ("LSM HOOK", str),
        ("Nr. PROGS", int),
        ("IDs", str),
    ]

    @classmethod
    def get_requirements(
        cls,
    ) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @staticmethod
    def _get_tramp_address(
        hook: interfaces.symbols.SymbolInterface,
        raw: bytes,
    ) -> Optional[int]:
        """If there is a BPF trampoline attached to the hook, returns
        its address."""
        # TODO: Disassembling sometimes fails. How can I know the size
        # of those stubs in advance?
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            mdisasm = takewhile(
                lambda insn: insn.mnemonic != "ret",
                md.disasm(raw, hook.address),
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
        tramp_address = next(
            (
                insn.op_str
                for insn in mdisasm
                if insn.mnemonic == "call"
            ),
            None,
        )
        if tramp_address:
            return int(tramp_address, 16)

    @classmethod
    def list_bpf_lsm(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
    ) -> Iterable[
        Tuple[interfaces.symbols.SymbolInterface, List[BpfProg]]
    ]:
        """Generates all the LSM hooks that have at least one BPF
        program attached"""
        vmlinux: interfaces.ModuleInterface = context.modules[
            symbol_table
        ]
        # Only tracing links can attach to the LSM hooks (true?)
        links: List[BpfLink] = list(
            (
                link
                for link in LinkList.list_links(
                    context,
                    symbol_table,
                    lambda link: link.typed_link.vol.get(
                        "type_name"
                    ).split(constants.BANG)[1]
                    != "bpf_tracing_link",
                )
            )
        )
        for hook in (
            vmlinux.get_symbol(sym)
            for sym in vmlinux.symbols
            if sym.startswith("bpf_lsm_")
        ):
            try:
                tramp_address = cls._get_tramp_address(
                    hook,
                    context.layers.read(
                        vmlinux.layer_name,
                        hook.address,
                        32,
                    ),
                )
            except PagedInvalidAddressException as E:
                # TODO: This should not happen... Figure out why it does
                # happen sometimes!
                vollog.warning(
                    "Unable to read instructions of trivial BPF LSM "
                    f"stub {hook.name} at {hex(hook.address)} ({E})",
                )
                continue
            if not tramp_address:
                # There is no BPF program on this hook.
                continue
            # Find the link(s) that attach program(s) to this hook.
            prog_list: List[BpfProg] = [
                link.prog
                for link in links
                if link.typed_link.trampoline.cur_image.image
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
    ) -> Iterable[Tuple[int, Tuple]]:
        """Generates the rows of the output."""
        symbol_table = self.config["kernel"]

        for hook, prog_list in self.list_bpf_lsm(
            self.context, symbol_table
        ):
            yield (
                0,
                (
                    hook.name,
                    len(prog_list),
                    ",".join((str(prog.aux.id) for prog in prog_list)),
                ),
            )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            self.columns,
            self._generator(),
        )
