import logging
from collections import namedtuple
from struct import unpack
from typing import List, ByteString, Iterable, Tuple
from hashlib import md5

from volatility3.framework import (
    interfaces,
    renderers,
    layers,
    exceptions,
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

class BtfExtract(interfaces.plugins.PluginInterface):
    """Extracts .BTF section(s) from the dump."""

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
    def _probably_valid_btf(
        cls,
        hdr: BtfHeader
    ) -> bool:
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
        if hdr.type_off >= hdr.str_off or hdr.type_off + hdr.type_len > hdr.str_off:
            return False
        if hdr.hdr_len + hdr.str_off + hdr.str_len > 2**29:
            return False
        return True

    @classmethod
    def _probably_kernel_btf(
        cls,
        hdr: BtfHeader
    ) -> bool:
        return hdr.hdr_len + hdr.str_off + hdr.str_len > 2**20

    @classmethod
    def btf_extract(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        kernel: bool = True,
    ) -> Iterable[Tuple[format_hints.Hex, bytes]]:
        """Extracts .BTF section(s) from the dump.
        kernel: only extract BTF of vmlinux image
        """
        layer = context.layers[layer_name]
        vollog.info(f"{layer.metadata.architecture=}")
        for offset in layer.scan(
            context=context,
            scanner=scanners.BytesScanner(b"\x9f\xeb"),
        ):
            hdr = BtfHeader(
                *unpack("<HBBIIIII", layer.read(offset, 24))
            )
            if not cls._probably_valid_btf(hdr):
                continue
            if kernel and not cls._probably_kernel_btf(hdr):
                continue
            vollog.info(f"{offset=}")
            vollog.info(f"{hdr=}")
            yield format_hints.Hex(offset), layer.read(
                offset, hdr.hdr_len + hdr.str_off + hdr.str_len
            )

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if isinstance(layer, layers.intel.Intel):
            layer = self.context.layers[layer.config["memory_layer"]]
        for offset, btf_section in self.btf_extract(
            self.context, layer.name
        ):
            h = md5()
            h.update(btf_section)

            filename = "_".join([hex(offset), h.digest().hex(), str(
                self.context.layers["base_layer"].location
            ).split("/")[-1] + ".btf"])
            with self.open(filename) as f:
                f.write(btf_section)

            yield 0, (offset, h.digest())

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Hash", bytes)],
            self._generator(),
        )
