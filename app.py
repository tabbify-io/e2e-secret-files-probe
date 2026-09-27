"""The probe the tenant file-secrets drill deploys.

One route, `GET /`, answers with what the guest can observe about the file
secret it was given — and never with the value itself:

* the two pointer variables the platform sets (`CERT_PATH` from the app's
  `[env]`, `TEST_CERT_FILE` from the supervisor's `<NAME>_FILE` convention);
* the file those pointers name: its SHA-256, size, mode and owner, next to the
  uid this process runs as;
* the SHA-256 and length of `PLAIN_TOKEN`, which a plain `secret:NAME`
  reference resolves into the environment by design;
* whether the value, in any encoding a platform could have used to carry it
  (raw, base64, hex), appears in the environment of PID 1, of this process, or
  of any other process whose environment this process may read, or on the
  kernel command line. The platform's init is non-dumpable and the app starts
  without `CAP_SYS_PTRACE`, so `/proc/1/environ` is normally closed to it; the
  kernel command line is what init's initial environment is built from, and
  it is world-readable.

A probe that could not LOOK is not a probe that found nothing: every environment
read reports whether it was readable, so the drill can refuse a vacuous "absent".

`GET /` is the only path the node's private diagnostic (`get_app`) fetches, so
the whole report lives there. Stdlib only, no build step.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: The port the drill's manifest declares in `[[runtime.ports]]`.
LISTEN_PORT = 8080
#: The `[env]` key whose value the platform rewrites to the file's guest path.
PATH_ENV = "CERT_PATH"
#: The supervisor's pointer for secret `TEST_CERT` (`<NAME>_FILE`).
POINTER_ENV = "TEST_CERT_FILE"
#: The supervisor's pointer to the secrets directory.
SECRETS_DIR_ENV = "TABBIFY_SECRETS_DIR"
#: The `[env]` key a plain `secret:NAME` reference resolves into.
TEXT_ENV = "PLAIN_TOKEN"
#: Distinctive slices of an encoding still identify a random value, and they
#: also catch a carrier that wrapped or truncated it.
WINDOW = 48


def needles(value: bytes) -> list[bytes]:
    """Every byte string whose presence in an environment means the value leaked."""
    b64 = base64.b64encode(value)
    hexed = value.hex().encode("ascii")
    found = [
        value,
        b64,
        base64.urlsafe_b64encode(value),
        hexed,
        hexed.upper(),
    ]
    middle = len(b64) // 2
    found.append(b64[middle : middle + WINDOW])
    middle = len(hexed) // 2
    found.append(hexed[middle : middle + WINDOW])
    return [needle for needle in found if len(needle) >= 16]


def file_facts(path: str | None) -> tuple[dict | None, bytes | None]:
    """What the file at `path` is, and its bytes (kept in memory only)."""
    if not path:
        return None, None
    facts: dict = {"path": path}
    try:
        info = os.stat(path)
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        facts.update(readable=False, error=f"{type(error).__name__}: {error.strerror}")
        return facts, None
    facts.update(
        readable=True,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        mode=stat.S_IMODE(info.st_mode),
        uid=info.st_uid,
        gid=info.st_gid,
    )
    return facts, data


def environ_facts(path: str, found: list[bytes]) -> dict:
    """Whether one `/proc/<pid>/environ` could be read, and whether it leaks."""
    try:
        with open(path, "rb") as handle:
            text = handle.read()
    except OSError as error:
        return {"readable": False, "error": f"{type(error).__name__}: {error.strerror}"}
    return {"readable": True, "leaks": any(needle in text for needle in found)}


def environ_report(proc_root: str, value: bytes | None) -> dict:
    """Scan PID 1, this process, every readable process and the kernel command
    line for the value."""
    if value is None:
        return {"checked": False, "reason": "no value to look for"}
    found = needles(value)
    pid1 = environ_facts(os.path.join(proc_root, "1", "environ"), found)
    own = environ_facts(os.path.join(proc_root, "self", "environ"), found)
    cmdline = environ_facts(os.path.join(proc_root, "cmdline"), found)
    scanned = readable = 0
    leaking: list[int] = []
    try:
        entries = sorted(int(name) for name in os.listdir(proc_root) if name.isdigit())
    except OSError:
        entries = []
    for pid in entries:
        scanned += 1
        facts = environ_facts(os.path.join(proc_root, str(pid), "environ"), found)
        if facts["readable"]:
            readable += 1
            if facts["leaks"]:
                leaking.append(pid)
    return {
        "checked": True,
        "pid1": pid1,
        "self": own,
        "cmdline": cmdline,
        "scanned": scanned,
        "readable": readable,
        "leaking_pids": leaking,
    }


def text_facts(value: str | None) -> dict:
    """Whether the plain secret arrived, as a digest and a length only."""
    if value is None:
        return {"set": False}
    data = value.encode("utf-8")
    return {"set": True, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def build_report(environ: dict, proc_root: str = "/proc") -> dict:
    """The whole answer of `GET /`. Contains digests and facts, never a value."""
    path = environ.get(PATH_ENV)
    facts, data = file_facts(path)
    return {
        "probe": "secret-files-drill",
        "uid": os.getuid(),
        "gid": os.getgid(),
        "path_env": path,
        "pointer_env": environ.get(POINTER_ENV),
        "secrets_dir_env": environ.get(SECRETS_DIR_ENV),
        "file": facts,
        "text": text_facts(environ.get(TEXT_ENV)),
        "environ": environ_report(proc_root, data),
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] != "/":
            self._reply(404, {"error": "no such route"})
            return
        try:
            self._reply(200, build_report(dict(os.environ)))
        except Exception as error:  # noqa: BLE001 — report, never crash the probe
            self._reply(500, {"error": type(error).__name__})

    def log_message(self, fmt: str, *args) -> None:
        print(f"[secret-files-probe] {fmt % args}", flush=True)


def main() -> None:
    print(f"[secret-files-probe] listening on 0.0.0.0:{LISTEN_PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
