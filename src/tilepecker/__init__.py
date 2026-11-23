import argparse
import curses
import logging
import os
import time
from collections import deque
from typing import Callable, Optional

from tlog_scales import backend, tiles
from tlog_scales.policy import Policy, Quorum, QuorumUnsatisfiedError
from tlog_scales.reader import TilesReader
from tlog_scales.signing import NoteSignature, Vkey, VkeySet
from tlog_scales.tlog import Checkpoint, InclusionProofInvalid

from .formats import FORMATTERS, IdentityFormatter, LeafFormatter


log = logging.getLogger("tilepecker")


class LoggingBackend:
    def __init__(self, inner: backend.TilesBackend):
        self.inner = inner

    def get(self, *path: str) -> bytes | None:
        name = "/".join(path)
        log.info("fetching %s", name)
        data = self.inner.get(*path)
        if data is None:
            log.warning("fetch of %s failed", name)
        return data


class CursesLogHandler(logging.Handler):
    def __init__(self, buf: deque):
        super().__init__()
        self.buf = buf

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            msg = record.getMessage()
        self.buf.append((record.levelno, msg))


class App:
    def __init__(self, reader: TilesReader, formatter: LeafFormatter,
                 vkeyset: Optional[VkeySet] = None,
                 policy: Optional[Policy] = None):
        self.reader = reader
        self.formatter = formatter
        self.vkeyset = vkeyset
        self.policy = policy
        self.quorum: Optional[Quorum] = None
        self.quorum_error: str = ""
        self.log_sig_ok: Optional[bool] = None

        self.checkpoint: Optional[Checkpoint] = None
        self.index: Optional[int] = None
        self.current_leaf: Optional[bytes] = None
        self.current_formatted: str = ""
        self.proof_ok: Optional[bool] = None
        self.proof_error: str = ""
        self.verified_sigs: set[NoteSignature] = set()

    def _verify_checkpoint_sigs(self) -> None:
        self.verified_sigs = set()
        if self.vkeyset is None or self.checkpoint is None:
            return

        cp = self.checkpoint

        valid = {sig for _, sig in self.vkeyset.verify(cp.signatures, cp)}
        self.verified_sigs = valid

        known = {(v.name, v.key_id) for v in self.vkeyset.keys.values()}
        for sig in cp.signatures:
            if (sig.name, sig.key_id) in known and sig not in valid:
                log.error("signature verification FAILED: %s", sig)

        log.info("checkpoint signatures verified: %d/%d",
                 len(valid), len(cp.signatures))

    def _check_policy(self) -> None:
        self.quorum = None
        self.quorum_error = ""
        self.log_sig_ok = None
        if self.policy is None or self.checkpoint is None:
            return

        cp = self.checkpoint

        # Policy.check() only evaluates the witness quorum, so check that one of
        # the policy's log keys has signed the checkpoint as well.
        log_keys = {vkey.identity() for vkey, _ in self.policy.logs}
        self.log_sig_ok = any((sig.name, sig.key_id) in log_keys
                              for sig in self.verified_sigs)
        if self.log_sig_ok:
            log.info("policy: checkpoint signed by a policy log key")
        else:
            log.error("policy: no valid signature from any policy log key")

        try:
            self.quorum = self.policy.check(cp)
            log.info("policy: witness quorum satisfied (timestamp %d)",
                     self.quorum.timestamp)
        except QuorumUnsatisfiedError:
            self.quorum_error = "unsatisfied"
            log.error("policy: witness quorum NOT satisfied")
        except Exception as e:
            self.quorum_error = f"error: {e}"
            log.error("policy: quorum check failed: %s", e)

    def refresh_checkpoint(self) -> None:
        cp = self.reader.get_checkpoint()
        self.checkpoint = cp
        log.info("checkpoint: origin=%s size=%d", cp.origin, cp.size)
        self._verify_checkpoint_sigs()
        self._check_policy()

        if self.index is not None and self.index >= cp.size:
            new_idx = max(0, cp.size - 1)
            log.warning("current index %d >= new size %d, clamping to %d",
                        self.index, cp.size, new_idx)
            self.load_leaf(new_idx)
        elif self.index is not None:
            self.load_leaf(self.index)

    def load_leaf(self, idx: int) -> None:
        assert self.checkpoint is not None
        cp = self.checkpoint

        if cp.size == 0:
            log.warning("log is empty, no leaves to load")
            return

        if idx < 0 or idx >= cp.size:
            log.warning("leaf index %d out of range [0, %d)", idx, cp.size)
            return

        leaf = self.reader.get_entry(idx)

        log.debug("building inclusion proof for leaf %d in tree of size %d", idx, cp.size)
        proof = self.reader.get_inclusion_proof(idx, cp.size)
        try:
            proof.check(tiles.leaf_hash(leaf), cp.root_hash)
            self.proof_ok = True
            self.proof_error = ""
        except InclusionProofInvalid as e:
            self.proof_ok = False
            self.proof_error = str(e)
            log.error("inclusion proof FAILED for leaf %d: %s", idx, e)

        try:
            self.current_formatted = self.formatter.format(leaf)
        except Exception as e:
            log.error("formatter %s failed on leaf %d: %s", self.formatter.name, idx, e)
            self.current_formatted = _hex_preview(leaf)

        self.current_leaf = leaf
        self.index = idx


def _hex_preview(data: bytes, limit: int = 512) -> str:
    head = data[:limit]
    out = []
    for i in range(0, len(head), 16):
        chunk = head[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        out.append(f"{i:08x}  {hex_part}")
    if len(data) > limit:
        out.append(f"... ({len(data) - limit} more bytes)")
    return "\n".join(out)


# signature type identifier bytes from c2sp.org/signed-note
SIG_TYPE_NAMES = {
    0x01: "ed25519-plain",
    0x02: "ecdsa",
    0x03: "reserved",
    0x04: "ed25519",
    0x05: "rfc6962",
    0x06: "mldsa44",
    **{t: "reserved" for t in range(0xfa, 0xff)},
    0xff: "unassigned",
}


def _sig_type_str(vkey: Vkey) -> str:
    return SIG_TYPE_NAMES.get(vkey.sig_type, str(vkey.sig_type))


def _sig_timestamp(vkey: Vkey, sig: NoteSignature) -> Optional[int]:
    """Timestamp embedded in a (timestamped cosignature) signature, if any."""
    try:
        verifier = vkey.get_verifier()
    except Exception:
        return None
    get_ts = getattr(verifier, "get_timestamp", None)
    if get_ts is None or len(sig.payload) < 8:
        return None
    return get_ts(sig.payload)


def _fmt_timestamp(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
    except (OverflowError, OSError, ValueError):
        return str(ts)


def draw_box(win, title: str) -> None:
    win.erase()
    win.box()
    _, w = win.getmaxyx()
    title_str = f" {title} "
    if w > len(title_str) + 4:
        win.addstr(0, 2, title_str, curses.A_BOLD)


def _safe_addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
    h, w = win.getmaxyx()
    if y < 1 or y >= h - 1:
        return
    max_w = w - x - 1
    if max_w <= 0:
        return
    try:
        win.addnstr(y, x, text, max_w, attr)
    except curses.error:
        pass


def _wrap_lines(text: str, width: int) -> list[str]:
    out = []
    for line in text.splitlines() or [""]:
        if not line:
            out.append("")
            continue
        for i in range(0, len(line), width):
            out.append(line[i:i+width])
    return out


def render_checkpoint_pane(win, app: App) -> None:
    draw_box(win, "Checkpoint")

    cp = app.checkpoint
    y = 2
    if cp is None:
        _safe_addstr(win, y, 2, "(no checkpoint fetched)")
        return

    _safe_addstr(win, y, 2, f"origin: {cp.origin}"); y += 1
    _safe_addstr(win, y, 2, f"size:   {cp.size}"); y += 1
    _safe_addstr(win, y, 2, f"root:   {cp.root_hash.hex()}"); y += 1
    if app.policy is not None:
        log_str = "OK" if app.log_sig_ok else "MISSING"
        if app.quorum is not None:
            ts = app.quorum.timestamp
            when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "-"
            q_str = f"OK (timestamp {ts}, {when})"
        else:
            q_str = app.quorum_error.upper()
        ok = app.log_sig_ok and app.quorum is not None
        _safe_addstr(win, y, 2, f"policy: log signature {log_str}, quorum {q_str}",
                     0 if ok else curses.A_BOLD)
        y += 1
    _safe_addstr(win, y, 2, f"signatures:", curses.A_BOLD); y += 1

    header, rows = _signature_table(app)
    _safe_addstr(win, y, 2, header, curses.A_UNDERLINE); y += 1
    for _, row in rows:
        _safe_addstr(win, y, 2, row)
        y += 1


def _signature_table(app: App) -> tuple[str, list[tuple[NoteSignature, str]]]:
    """Header and per-signature rows for the checkpoint's signature table."""
    assert app.checkpoint is not None
    cp = app.checkpoint
    name_w = max((len(s.name) for s in cp.signatures), default=4)
    name_w = max(name_w, len("name"))
    payload_w = max((len(_payload_summary(s.payload)) for s in cp.signatures), default=len("payload"))
    payload_w = max(payload_w, len("payload"))
    has_vkeys = app.vkeyset is not None
    keys: dict[tuple[str, int], Vkey] = {}
    if has_vkeys and app.vkeyset is not None:
        keys = {(v.name, v.key_id): v for v in app.vkeyset.keys.values()}

    types = {k: _sig_type_str(v) for k, v in keys.items()}
    type_w = max((len(t) for t in types.values()), default=len("type"))
    type_w = max(type_w, len("type"))

    roles: dict[tuple[str, int], str] = {}
    if app.policy is not None:
        for vkey, _ in app.policy.logs:
            roles[vkey.identity()] = "log"
        roles.update(app.policy.witness_names)
    role_w = max((len(r) for r in roles.values()), default=0)
    role_w = max(role_w, len("policy")) if roles else 0
    role_hdr = f"  {'policy'.ljust(role_w)}" if role_w else ""

    timestamps: dict[NoteSignature, str] = {}
    for sig in cp.signatures:
        vkey = keys.get((sig.name, sig.key_id))
        if vkey is not None and (ts := _sig_timestamp(vkey, sig)) is not None:
            timestamps[sig] = _fmt_timestamp(ts)
    ts_label = "timestamp (UTC)"
    ts_w = max((len(t) for t in timestamps.values()), default=0)
    ts_w = max(ts_w, len(ts_label)) if timestamps else 0
    ts_hdr = f"  {ts_label.ljust(ts_w)}" if ts_w else ""

    header = (f"  {'ok':<2}  {'name'.ljust(name_w)}  {'key_id'.ljust(8)}  "
              f"{'type'.ljust(type_w)}{role_hdr}{ts_hdr}  {'payload'.ljust(payload_w)}")
    rows = []
    for sig in cp.signatures:
        known = (sig.name, sig.key_id) in keys
        if not has_vkeys:
            mark = "-"
        elif sig in app.verified_sigs:
            mark = "OK"
        elif known:
            mark = "X"
        else:
            mark = "?"
        sig_type = types.get((sig.name, sig.key_id), "?")
        role = f"  {roles.get((sig.name, sig.key_id), '-').ljust(role_w)}" if role_w else ""
        ts_col = f"  {timestamps.get(sig, '-').ljust(ts_w)}" if ts_w else ""
        row = (f"  {mark:<2}  {sig.name.ljust(name_w)}  {sig.key_id:08x}  "
               f"{sig_type.ljust(type_w)}{role}{ts_col}  {_payload_summary(sig.payload).ljust(payload_w)}")
        rows.append((sig, row))
    return header, rows


def _payload_summary(payload: bytes, limit: int = 16) -> str:
    head = payload[:limit].hex()
    if len(payload) > limit:
        head += "…"
    return f"{head} ({len(payload)} bytes)"


def render_leaf_pane(win, app: App) -> None:
    parts = []
    if app.index is not None:
        parts.append(f"Leaf {app.index}")
    else:
        parts.append("Leaf")
    if app.current_leaf is not None:
        parts.append(f"{len(app.current_leaf)} bytes")
        parts.append(f"hash={tiles.leaf_hash(app.current_leaf).hex()}")
    if app.proof_ok is False:
        parts.append(f"proof=FAIL({app.proof_error})")
    title = " | ".join(parts)
    draw_box(win, title)
    h, w = win.getmaxyx()

    if not app.current_formatted:
        _safe_addstr(win, 2, 2, "(no leaf loaded)")
        return

    inner_w = max(1, w - 4)
    lines = _wrap_lines(app.current_formatted, inner_w)

    max_rows = h - 3
    for i, line in enumerate(lines[:max_rows]):
        _safe_addstr(win, 1 + i, 2, line)


def render_cache_pane(win, app: App) -> None:
    draw_box(win, "Tile cache (LRU → MRU)")
    h, _ = win.getmaxyx()
    max_rows = h - 3
    if max_rows <= 0:
        return

    entries = list(app.reader.tile_cache.tiles.items())
    header = f"  {'L':>3}  {'N':>6}  {'len':>4}"
    _safe_addstr(win, 1, 1, header, curses.A_UNDERLINE)

    visible = entries[-max_rows:]
    for i, ((l, n), tile) in enumerate(visible):
        row = f"  {l:>3}  {n:>6}  {tile.length:>4}"
        _safe_addstr(win, 2 + i, 1, row)


def render_log_pane(win, log_buf: deque) -> None:
    draw_box(win, "Log")
    h, _ = win.getmaxyx()

    max_rows = h - 2
    if max_rows <= 0:
        return

    entries = list(log_buf)[-max_rows:]
    for i, (level, msg) in enumerate(entries):
        attr = curses.A_BOLD if level >= logging.ERROR else 0
        _safe_addstr(win, 1 + i, 2, msg, attr)


HOTKEY_HELP = [
    ("q",         "Quit"),
    ("r",         "Re-fetch checkpoint"),
    ("h, ?",      "Show this help"),
    ("w",         "Write current leaf to a file"),
    ("s",         "Signatures dialog (Enter shows full payload, w saves it)"),
    ("g",         "Go to leaf index (negative = from end; Esc to cancel)"),
    ("n, Right",  "Next leaf"),
    ("p, Left",   "Previous leaf"),
    ("Home",      "First leaf"),
    ("End",       "Last leaf"),
]


def _popup_window(stdscr, height: int, width: int):
    sh, sw = stdscr.getmaxyx()
    height = min(height, sh - 2)
    width = min(width, sw - 2)
    y = max(0, (sh - height) // 2)
    x = max(0, (sw - width) // 2)
    win = curses.newwin(height, width, y, x)
    win.keypad(True)
    return win


def show_help_popup(stdscr) -> None:
    key_w = max(len(k) for k, _ in HOTKEY_HELP)
    rows = [f"  {k.ljust(key_w)}  {d}" for k, d in HOTKEY_HELP]
    width = max(len(r) for r in rows) + 4
    width = max(width, len(" Hotkeys ") + 4)
    height = len(rows) + 4

    win = _popup_window(stdscr, height, width)
    win.timeout(-1)
    draw_box(win, "Hotkeys")
    for i, row in enumerate(rows):
        _safe_addstr(win, 1 + i, 1, row)
    _safe_addstr(win, height - 2, 1, "  (press any key to close)", curses.A_DIM)
    win.refresh()
    win.getch()


def _scroll_key(key: int, pos: int, count: int, page: int) -> int:
    """New position after a navigation key, clamped to [0, count)."""
    if key in (curses.KEY_UP, ord("k")):
        pos -= 1
    elif key in (curses.KEY_DOWN, ord("j")):
        pos += 1
    elif key == curses.KEY_PPAGE:
        pos -= page
    elif key == curses.KEY_NPAGE:
        pos += page
    elif key == curses.KEY_HOME:
        pos = 0
    elif key == curses.KEY_END:
        pos = count - 1
    return max(0, min(pos, count - 1))


def show_signatures_popup(stdscr, app: App, redraw: Callable[[], None]) -> None:
    if app.checkpoint is None or not app.checkpoint.signatures:
        log.warning("no signatures to show")
        return
    header, rows = _signature_table(app)
    sh, sw = stdscr.getmaxyx()
    width = max(len(header), *(len(r) for _, r in rows)) + 4
    height = len(rows) + 5
    sel = 0
    top = 0
    while True:
        win = _popup_window(stdscr, height, width)
        win.timeout(-1)
        h, _ = win.getmaxyx()
        visible = max(1, h - 4)
        top = min(max(top, sel - visible + 1), sel)
        draw_box(win, f"Signatures ({len(rows)})")
        _safe_addstr(win, 1, 1, header, curses.A_UNDERLINE)
        for i, (_, row) in enumerate(rows[top:top + visible]):
            attr = curses.A_REVERSE if top + i == sel else 0
            _safe_addstr(win, 2 + i, 1, row, attr)
        _safe_addstr(win, h - 2, 1, "  Up/Down select, Enter payload, w save, Esc/q close",
                     curses.A_DIM)
        win.refresh()
        key = win.getch()
        if key in (27, ord("q"), ord("s")):
            return
        if key in (curses.KEY_ENTER, 10, 13):
            show_payload_popup(stdscr, app, rows[sel][0], redraw)
            redraw()
        elif key == ord("w"):
            save_payload(stdscr, rows[sel][0], redraw)
        elif key == curses.KEY_RESIZE:
            redraw()
        else:
            sel = _scroll_key(key, sel, len(rows), visible)


def show_payload_popup(stdscr, app: App, sig: NoteSignature,
                       redraw: Callable[[], None]) -> None:
    keys = {}
    if app.vkeyset is not None:
        keys = {(v.name, v.key_id): v for v in app.vkeyset.keys.values()}
    vkey = keys.get((sig.name, sig.key_id))
    info = [
        f"name:    {sig.name}",
        f"key_id:  {sig.key_id:08x}",
        f"type:    {_sig_type_str(vkey) if vkey else '?'}",
    ]
    if vkey is not None and (ts := _sig_timestamp(vkey, sig)) is not None:
        info.append(f"time:    {_fmt_timestamp(ts)} UTC")
    info.append(f"length:  {len(sig.payload)} bytes")
    info.append("")
    lines = info + _hex_preview(sig.payload, limit=len(sig.payload)).splitlines()
    width = max(len(l) for l in lines) + 6
    height = len(lines) + 4
    top = 0
    while True:
        win = _popup_window(stdscr, height, width)
        win.timeout(-1)
        h, _ = win.getmaxyx()
        visible = max(1, h - 3)
        max_top = max(0, len(lines) - visible)
        top = min(top, max_top)
        draw_box(win, "Signature payload")
        for i, line in enumerate(lines[top:top + visible]):
            _safe_addstr(win, 1 + i, 2, line)
        hint = "  w save, Esc/q close"
        if max_top:
            hint = (f"  [{top + 1}-{min(top + visible, len(lines))}/{len(lines)}] "
                    "Up/Down scroll, w save, Esc/q close")
        _safe_addstr(win, h - 2, 1, hint, curses.A_DIM)
        win.refresh()
        key = win.getch()
        if key in (27, ord("q"), curses.KEY_ENTER, 10, 13):
            return
        if key == ord("w"):
            save_payload(stdscr, sig, redraw)
        elif key == curses.KEY_RESIZE:
            redraw()
        else:
            top = _scroll_key(key, top, max_top + 1, visible)


def prompt_text(stdscr, title: str, label: str, initial: str = "",
                accept: Callable[[str, str], bool] = lambda buf, c: c.isprintable(),
                width: int = 40) -> Optional[str]:
    """Single-line input popup. Returns None on Esc or empty input."""
    height = 5
    win = _popup_window(stdscr, height, width)
    win.timeout(-1)
    _, w = win.getmaxyx()
    field_w = max(1, w - 6)
    curses.curs_set(1)
    try:
        buf = initial
        while True:
            draw_box(win, title)
            _safe_addstr(win, 1, 2, label)
            shown = buf[-(field_w - 1):] if len(buf) >= field_w else buf
            _safe_addstr(win, 2, 2, "> " + shown.ljust(field_w))
            win.move(2, 4 + len(shown))
            win.refresh()
            ch = win.getch()
            if ch == 27:  # Esc
                return None
            if ch in (curses.KEY_ENTER, 10, 13):
                return buf or None
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                buf = buf[:-1]
                continue
            if 0 <= ch < 256 and accept(buf, chr(ch)):
                buf += chr(ch)
    finally:
        curses.curs_set(0)


def prompt_integer(stdscr, title: str) -> Optional[int]:
    buf = prompt_text(stdscr, title, "Enter index (Esc cancels):",
                      accept=lambda buf, c: c.isdigit() or (c == "-" and not buf))
    if buf is None:
        return None
    try:
        return int(buf)
    except ValueError:
        return None


def _default_payload_filename(sig: NoteSignature) -> str:
    name = "".join(c if c.isalnum() or c in "-._" else "_" for c in sig.name)
    return f"{name}+{sig.key_id:08x}.sig"


def save_payload(stdscr, sig: NoteSignature, redraw: Callable[[], None]) -> None:
    save_bytes(stdscr, sig.payload, _default_payload_filename(sig),
               f"payload of {sig.name}+{sig.key_id:08x}", "Save payload", redraw)


def save_bytes(stdscr, data: bytes, default_name: str, what: str, title: str,
               redraw: Callable[[], None]) -> None:
    """Prompt for a filename and write data there."""
    sw = stdscr.getmaxyx()[1]
    path = prompt_text(stdscr, title, "File name (Esc cancels):",
                       initial=default_name,
                       width=min(max(60, sw * 2 // 3), sw - 2))
    redraw()
    if path is None:
        return
    path = os.path.expanduser(path)
    if os.path.exists(path):
        question = f"{path} exists, overwrite? (y/N)"
        answer = prompt_text(stdscr, title, question,
                             accept=lambda buf, c: not buf and c in "yYnN",
                             width=max(40, len(question) + 4))
        redraw()
        if answer is None or answer.lower() != "y":
            log.info("not overwriting %s", path)
            return
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as e:
        log.error("saving %s failed: %s", what, e)
        return
    log.info("saved %d byte %s to %s", len(data), what, path)
    redraw()


def draw_main(stdscr, app: App, log_buf: deque) -> None:
    h, w = stdscr.getmaxyx()
    cp_h = max(3, h // 6)
    log_h = max(3, h // 6)
    leaf_h = max(3, h - cp_h - log_h)

    cache_w = max(28, w // 4)
    log_w = max(1, w - cache_w)

    top = curses.newwin(cp_h, w, 0, 0)
    middle = curses.newwin(leaf_h, w, cp_h, 0)
    bottom_log = curses.newwin(log_h, log_w, cp_h + leaf_h, 0)
    bottom_cache = curses.newwin(log_h, cache_w, cp_h + leaf_h, log_w)

    render_checkpoint_pane(top, app)
    render_leaf_pane(middle, app)
    render_log_pane(bottom_log, log_buf)
    render_cache_pane(bottom_cache, app)

    stdscr.noutrefresh()
    top.noutrefresh()
    middle.noutrefresh()
    bottom_log.noutrefresh()
    bottom_cache.noutrefresh()
    curses.doupdate()


def cmain(stdscr, app: App, log_buf: deque, initial_index: Optional[int]) -> None:
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(150)
    curses.start_color()
    curses.use_default_colors()

    try:
        app.refresh_checkpoint()
        if app.checkpoint is not None and app.checkpoint.size > 0:
            idx = initial_index if initial_index is not None else app.checkpoint.size - 1
            app.load_leaf(idx)
    except Exception as e:
        log.error("startup failed: %s", e)

    while True:
        draw_main(stdscr, app, log_buf)

        try:
            key = stdscr.getch()
        except KeyboardInterrupt:
            break

        if key == -1:
            continue

        try:
            if key == ord("q"):
                break
            elif key == ord("r"):
                app.refresh_checkpoint()
            elif key in (ord("h"), ord("?")):
                show_help_popup(stdscr)
                stdscr.erase()
            elif key == ord("s"):
                show_signatures_popup(stdscr, app,
                                      lambda: draw_main(stdscr, app, log_buf))
                stdscr.erase()
            elif key == ord("w"):
                if app.current_leaf is None or app.index is None:
                    log.warning("no leaf loaded")
                else:
                    save_bytes(stdscr, app.current_leaf, f"leaf-{app.index}.bin",
                               f"leaf {app.index}", "Save leaf",
                               lambda: draw_main(stdscr, app, log_buf))
                stdscr.erase()
            elif key == ord("g"):
                target = prompt_integer(stdscr, "Go to leaf")
                stdscr.erase()
                if target is not None:
                    if target < 0 and app.checkpoint is not None:
                        target = app.checkpoint.size + target
                    app.load_leaf(target)
            elif key in (curses.KEY_LEFT, ord("p"), ord("P")):
                if app.index is not None:
                    app.load_leaf(app.index - 1)
            elif key in (curses.KEY_RIGHT, ord("n"), ord("N")):
                if app.index is not None:
                    app.load_leaf(app.index + 1)
            elif key == curses.KEY_HOME:
                if app.checkpoint is not None:
                    app.load_leaf(0)
            elif key == curses.KEY_END:
                if app.checkpoint is not None:
                    app.load_leaf(app.checkpoint.size - 1)
            elif key == curses.KEY_RESIZE:
                stdscr.erase()
        except Exception as e:
            log.error("error handling key: %s", e)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tilepecker",
                                     description="Interactive transparency log inspector")
    parser.add_argument("location", nargs="?", default=None,
                        help="Log location (local path, file:// or http(s):// URL); "
                             "with --policy, select a log by URL or unique substring; "
                             "may be omitted if --policy names exactly one log with a URL")
    parser.add_argument("--format", "-f", choices=sorted(FORMATTERS.keys()),
                        default="binary",
                        help="Leaf formatter (default: binary)")
    parser.add_argument("--leaf", "-n", type=int, default=None,
                        help="Initial leaf index (default: latest)")
    parser.add_argument("--vkey", action="append", default=[],
                        help="Verification key in 'name+keyid+b64' form, or @FILE to "
                             "read one vkey per line from FILE (repeatable)")
    parser.add_argument("--policy", metavar="FILE", default=None,
                        help="Trust policy file; its log and witness keys are "
                             "used for verification and the witness quorum is checked")
    parser.add_argument("--policy-format", choices=["auto", "c2sp", "sigsum"], default="auto",
                        help="Key format used in the policy file (default: auto)")
    parser.add_argument("--preimage", action="append", default=[], metavar="TEXT",
                        help="Context key/value preimage for the identity format, "
                             "matched against H(H(TEXT)); @FILE reads one preimage "
                             "per line from FILE, no comments (repeatable)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable DEBUG logging")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    log_buf: deque = deque(maxlen=500)
    handler = CursesLogHandler(log_buf)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s",
                                           datefmt="%H:%M:%S"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    formatter: LeafFormatter
    if args.format == "identity":
        preimages: list[str] = []
        for arg in args.preimage:
            if arg.startswith("@"):
                path = arg[1:]
                try:
                    with open(path, encoding="utf-8", newline="") as f:
                        lines = [line.removesuffix("\n").removesuffix("\r") for line in f]
                except (OSError, UnicodeDecodeError) as e:
                    parser.error(f"failed to load preimages from {path}: {e}")
                preimages += [line for line in lines if line]
            else:
                preimages.append(arg)
        formatter = IdentityFormatter(preimages)
    else:
        if args.preimage:
            parser.error("--preimage requires --format identity")
        formatter = FORMATTERS[args.format]()

    policy: Optional[Policy] = None
    if args.policy is not None:
        is_sigsum = {"auto": None, "c2sp": False, "sigsum": True}[args.policy_format]
        try:
            with open(args.policy) as f:
                policy = Policy.from_text(f.read(), is_sigsum=is_sigsum)
        except (OSError, ValueError) as e:
            parser.error(f"failed to load policy {args.policy}: {e}")

    location = args.location
    if policy is not None:
        urls = [url for _, url in policy.logs if url]
        if location is not None:
            urls = [url for url in urls if location in url]
            if not urls:
                parser.error(f"no log URL in policy matches {location!r}")
            if len(urls) > 1:
                parser.error(f"multiple log URLs in policy match {location!r}: " + ", ".join(urls))
        if len(urls) != 1:
            parser.error("location is required unless --policy names exactly one log with a URL; "
                         "provide a log URL or unique substring as the location")
        location = urls[0]
    elif location is None:
        parser.error("location is required unless --policy names exactly one log with a URL")

    vkeys: list[Vkey] = []
    for arg in args.vkey:
        if arg.startswith("@"):
            path = arg[1:]
            try:
                with open(path) as f:
                    lines = [line.strip() for line in f]
                vkeys += [Vkey.from_string(line) for line in lines
                          if line and not line.startswith("#")]
            except (OSError, ValueError) as e:
                parser.error(f"failed to load vkeys from {path}: {e}")
        else:
            vkeys.append(Vkey.from_string(arg))
    if policy is not None:
        vkeys += [vkey for vkey, _ in policy.logs]
        vkeys += [e for e in policy.entities.values() if isinstance(e, Vkey)]

    vkeyset: Optional[VkeySet] = None
    if vkeys:
        vkeyset = VkeySet(*vkeys)
        for vk in vkeyset.keys.values():
            log.info("loaded vkey: %s", vk)

    if policy is not None:
        log.info("loaded policy %s: %d log(s), %d entities, quorum=%s", args.policy,
                 len(policy.logs), len(policy.entities), policy.entry_point or "none")

    be = LoggingBackend(backend.make_backend(location))
    reader = TilesReader(be)
    app = App(reader, formatter, vkeyset=vkeyset, policy=policy)

    curses.wrapper(cmain, app, log_buf, args.leaf)
