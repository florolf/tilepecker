import json
from typing import Protocol


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


FORMATTERS: dict[str, type[LeafFormatter]] = {
    "binary": BinaryFormatter,
    "json": JsonFormatter,
    "sigsum": SigsumFormatter,
    "utf8": Utf8Formatter,
}
