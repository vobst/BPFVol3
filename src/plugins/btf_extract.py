import logging
import tempfile
from collections import namedtuple
from struct import unpack
from typing import List, Generator, Iterable, Tuple
from hashlib import md5
from subprocess import run, DEVNULL, CalledProcessError
import re

from volatility3.framework import (
    interfaces,
    renderers,
    layers,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


BtfHeader = namedtuple(
    "BtfHeader",
    [
        "magic",
        "version",
        "flags",
        "hdr_len",
        "type_off",
        "type_len",
        "str_off",
        "str_len",
    ],
)
setattr(BtfHeader, "sizeof", 24)


class BtfExtract(interfaces.plugins.PluginInterface):
    """Extracts .BTF section(s) from the dump."""

    MAGIC_BTF = b"\x9f\xeb"

    _required_framework_version = (2, 0, 0)
    _version = (0, 0, 0)

    @classmethod
    def get_requirements(
        cls,
    ) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer to scan",
            ),
        ]

    @classmethod
    def _probably_valid_btf(cls, hdr: BtfHeader) -> bool:
        if (
            hdr.version != 1
            or hdr.flags != 0
            or hdr.hdr_len != 24
            or hdr.type_off != 0
            or hdr.str_off == 0
            or hdr.type_len == 0
            or hdr.str_len == 0
        ):
            return False
        if (
            hdr.type_off >= hdr.str_off
            or hdr.type_off + hdr.type_len > hdr.str_off
        ):
            return False
        if hdr.hdr_len + hdr.str_off + hdr.str_len > 2**29:
            return False
        return True

    @classmethod
    def _likely_valid_btf(cls, btf: bytes) -> bool:
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(btf)
            try:
                run(
                    ["bpftool", "btf", "dump", "file", f"{tmp.name}"],
                    stdout=DEVNULL,
                    stderr=DEVNULL,
                    timeout=10,
                    check=True,
                )
                run(
                    ["pahole", "-F", "btf", f"{tmp.name}"],
                    stdout=DEVNULL,
                    stderr=DEVNULL,
                    timeout=10,
                    check=True,
                )
            except CalledProcessError as E:
                vollog.info(
                    f"BTF cannot be parsed by cli tools: {E.cmd} {E.stderr}"
                )
                return False
            return True

    @classmethod
    def _probably_kernel_btf(cls, hdr: BtfHeader) -> bool:
        return hdr.hdr_len + hdr.str_off + hdr.str_len > 2**20

    @classmethod
    def _likely_kernel_btf(cls, btf: bytes) -> bool:
        kernel_strs = re.compile(
            b"(__sys_setuid|__sys_setsockopt|__sys_bpf)"
        )
        if not re.search(kernel_strs, btf):
            vollog.info(
                f"BTF does not contain characteristic kernel strings"
            )
            return False
        return True

    @classmethod
    def btf_extract(
        cls,
        context: interfaces.context.ContextInterface,
        phys_layer: interfaces.layers.TranslationLayerInterface,
        kernel: bool = True,
    ) -> Iterable[Tuple[format_hints.Hex, bytes]]:
        """Extracts .BTF section(s) from the dump.
        kernel: attempt to only extract BTF of vmlinux image (we also
            find BTF of kernel modules or BPF objects)
        """
        for offset in phys_layer.scan(
            context=context,
            scanner=scanners.BytesScanner(cls.MAGIC_BTF),
        ):
            hdr = BtfHeader(
                *unpack(
                    "<HBBIIIII",
                    phys_layer.read(offset, BtfHeader.sizeof),
                )
            )
            if not cls._probably_valid_btf(hdr):
                continue
            if kernel and not cls._probably_kernel_btf(hdr):
                continue
            btf = phys_layer.read(
                offset, hdr.hdr_len + hdr.str_off + hdr.str_len
            )
            if not cls._likely_valid_btf(btf):
                continue
            if kernel and not cls._likely_kernel_btf(btf):
                continue
            vollog.info(f"Found likely valid BTF: {offset=} {hdr=}")
            yield format_hints.Hex(offset), btf

    def _generator(
        self,
    ) -> Generator[
        Tuple[int, Tuple[format_hints.Hex, str]], None, None
    ]:
        layer = self.context.layers[self.config["primary"]]
        if isinstance(layer, layers.intel.Intel):
            virt_layer = layer
            phys_layer = self.context.layers[
                layer.config["memory_layer"]
            ]
        else:
            virt_layer = None
            phys_layer = layer
        for offset, btf_section in self.btf_extract(
            self.context, phys_layer
        ):
            h = md5()
            h.update(btf_section)
            m = h.digest().hex()

            filename = "_".join(
                [
                    hex(offset),
                    m,
                    str(
                        self.context.layers["base_layer"].location
                    ).split("/")[-1]
                    + ".btf",
                ]
            )
            with self.open(filename) as f:
                f.write(btf_section)

            yield 0, (offset, m)

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("MD5", str)],
            self._generator(),
        )
