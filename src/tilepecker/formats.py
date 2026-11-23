import hashlib
import json
from typing import Iterable, Protocol


class LeafFormatter(Protocol):
    name: str

    def format(self, raw: bytes) -> str: ...


class BinaryFormatter:
    name = "binary"

    def format(self, raw: bytes) -> str:
        out = []
        for off in range(0, len(raw), 16):
            chunk = raw[off:off + 16]
            left = " ".join(f"{b:02x}" for b in chunk[:8])
            right = " ".join(f"{b:02x}" for b in chunk[8:])
            hex_part = f"{left:<23}  {right:<23}"
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            out.append(f"{off:08x}  {hex_part}  |{ascii_part}|")
        return "\n".join(out)


class Utf8Formatter:
    name = "utf8"

    def format(self, raw: bytes) -> str:
        text = raw.decode("utf-8", errors="replace")
        out = []
        for ch in text:
            cp = ord(ch)
            if ch in ("\n", "\t"):
                out.append(ch)
            elif cp < 0x20 or cp == 0x7f:
                out.append(f"\\x{cp:02x}")
            else:
                out.append(ch)
        return "".join(out)


class JsonFormatter:
    name = "json"

    def format(self, raw: bytes) -> str:
        return json.dumps(json.loads(raw), indent=2, sort_keys=True)


class SigsumFormatter:
    name = "sigsum"

    FIELDS = [
        ("checksum",  32),
        ("signature", 64),
        ("key_hash",  32),
    ]
    EXPECTED_LEN = sum(n for _, n in FIELDS)

    def format(self, raw: bytes) -> str:
        if len(raw) != self.EXPECTED_LEN:
            raise ValueError(
                f"sigsum leaf must be exactly {self.EXPECTED_LEN} bytes, got {len(raw)}"
            )

        label_w = max(len(name) for name, _ in self.FIELDS)
        out = []
        off = 0
        for name, length in self.FIELDS:
            out.append(f"{name.ljust(label_w)}  {raw[off:off + length].hex()}")
            off += length
        return "\n".join(out)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class IdentityFormatter:
    """c2sp.org/identity-transparency leaf entry, version 0x01."""

    name = "identity"

    VERSION = 0x01
    HEADER_LEN = 1 + 32 + 32
    TRAILER_LEN = 32
    PAIR_LEN = 64

    def __init__(self, preimages: Iterable[str] = ()):
        self._lookup: dict[bytes, str] = {
            _sha256(_sha256(p.encode("utf-8"))): p for p in preimages
        }

    def _resolve(self, digest: bytes) -> str:
        """The quoted preimage if known, else the hex digest."""
        pre = self._lookup.get(digest)
        if pre is None:
            return digest.hex()
        return json.dumps(pre, ensure_ascii=False)

    def format(self, raw: bytes) -> str:
        min_len = self.HEADER_LEN + self.TRAILER_LEN
        if not raw:
            raise ValueError("identity leaf is empty")
        if raw[0] != self.VERSION:
            raise ValueError(f"unsupported identity leaf version 0x{raw[0]:02x}")
        if len(raw) < min_len or (len(raw) - min_len) % self.PAIR_LEN != 0:
            raise ValueError(
                f"identity leaf must be {min_len} + 64*N bytes, got {len(raw)}"
            )

        label_w = len("root_of_trust")
        out = [
            f"{'version'.ljust(label_w)}  0x{raw[0]:02x}",
            f"{'root_of_trust'.ljust(label_w)}  {raw[1:33].hex()}",
            f"{'message_hash'.ljust(label_w)}  {raw[33:65].hex()}",
        ]

        receipt = raw[len(raw) - self.TRAILER_LEN:]
        receipt_text = "none" if receipt == bytes(32) else receipt.hex()
        out.append(f"{'receipt_hash'.ljust(label_w)}  {receipt_text}")

        ctx = raw[self.HEADER_LEN:len(raw) - self.TRAILER_LEN]
        keys = []
        if ctx:
            out.append("context")
        if keys != sorted(keys):
            out.append("warning: context keys not sorted")

        for off in range(0, len(ctx), self.PAIR_LEN):
            k = ctx[off:off + 32]
            v = ctx[off + 32:off + 64]
            keys.append(k)
            out.append(f"  {self._resolve(k)} {self._resolve(v)}")

        return "\n".join(out)


FORMATTERS: dict[str, type[LeafFormatter]] = {
    "binary": BinaryFormatter,
    "identity": IdentityFormatter,
    "json": JsonFormatter,
    "sigsum": SigsumFormatter,
    "utf8": Utf8Formatter,
}
