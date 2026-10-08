from __future__ import annotations

import asyncio
import fcntl
import hashlib
import hmac
import json
import os
import re
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

# Single-purpose blob store for RustDrop. Never reachable from outside the
# internal-only network segment it shares with RDS, and never talks to
# Postgres or knows about device identity at all - RDS's own API is the
# only caller, and it has already authorized the request (sender owns the
# drop, recipient is the addressee) before it ever gets here. This process
# only knows "some caller holding the shared secret asked for blob X."
STORAGE_ROOT = Path("/mnt/rustdrop-storage/blobs")
STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
SHARED_SECRET = os.environ.get("RUSTDROP_STORAGE_SECRET", "")

# Refuse to start at all on a missing/empty/trivially short secret rather
# than serving with it - an empty one makes the expected header exactly
# "Bearer ", which a caller holding no secret at all trivially matches.
# Only the length is ever reported, never the value.
MIN_SHARED_SECRET_LENGTH = 16
if len(SHARED_SECRET.strip()) < MIN_SHARED_SECRET_LENGTH:
    raise RuntimeError(
        f"RUSTDROP_STORAGE_SECRET is unset or shorter than {MIN_SHARED_SECRET_LENGTH} "
        "characters - refusing to start"
    )

# How long a download will keep waiting for more bytes to appear on an
# in-progress upload before giving up (tail-following - see doc section 05).
TAIL_IDLE_TIMEOUT_SECONDS = 600
TAIL_POLL_INTERVAL_SECONDS = 0.5

# No /docs, /redoc or /openapi.json - FastAPI serves those without going
# through _check_auth, and RDS (the only caller) never needs them.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _check_auth(authorization: str | None) -> None:
    expected = f"Bearer {SHARED_SECRET}"
    # Compared as bytes: hmac.compare_digest() raises TypeError (a 500, not
    # a 401) for a str argument containing any non-ASCII character, and the
    # header value is caller-controlled.
    if not authorization or not hmac.compare_digest(
        authorization.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="unauthorized")


def _blob_path(key: str) -> Path:
    # storage_key is always a server-generated UUID minted by RDS
    # (rustdrop.py), never client-controlled - this check is defense in
    # depth, not the primary guarantee against path traversal.
    if not key or "/" in key or "\\" in key or ".." in key:
        raise HTTPException(status_code=400, detail="invalid key")
    return STORAGE_ROOT / key


def _marker_path(key: str) -> Path:
    # Presence of this file means "upload still in progress" - the
    # download side polls for it going away to know when to stop
    # tail-following and treat the blob as final. Content is JSON
    # ({"upload_length": N}) rather than an empty sentinel now that a
    # resumable upload needs to remember the declared total across
    # separate part requests.
    return _blob_path(key).with_suffix(".uploading")


def _sha256_sidecar_path(key: str) -> Path:
    # Written once, after the upload completes - its presence doubles as
    # "this blob finished uploading cleanly" independent of the .uploading
    # marker (which only tracks in-progress-ness, not correctness).
    return _blob_path(key).with_suffix(".sha256")


def _lock_path(key: str) -> Path:
    return _blob_path(key).with_suffix(".lock")


@contextmanager
def _blob_lock(key: str):
    # Today's single-request-does-everything upload had no concurrent-
    # writer risk; resumable multi-request uploads do, even though
    # RustDrop's own client never intentionally overlaps two part-PUTs for
    # the same key - defense in depth, not a correctness dependency.
    lock_file = open(_lock_path(key), "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()


def _current_blob_size(key: str) -> int:
    path = _blob_path(key)
    return path.stat().st_size if path.exists() else 0


def _read_uploading_marker(key: str) -> dict | None:
    marker = _marker_path(key)
    if not marker.exists():
        return None
    try:
        return json.loads(marker.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _write_uploading_marker(key: str, *, upload_length: int) -> None:
    _marker_path(key).write_text(json.dumps({"upload_length": upload_length}))


def _discard_upload(key: str) -> None:
    # Blob and sidecar first, marker last: a download tail-following this
    # upload keeps seeing "still uploading" until the data is already gone,
    # then sees the marker vanish with no digest behind it - which
    # download_blob's tail_follow treats as a failed upload, not a finished
    # one. The lock file is deliberately left alone (unlinking a lock file
    # another request may hold would let a third open a fresh one).
    _blob_path(key).unlink(missing_ok=True)
    _sha256_sidecar_path(key).unlink(missing_ok=True)
    _marker_path(key).unlink(missing_ok=True)


def _parse_length_header(value: str, name: str) -> int:
    # Non-negative decimal integer only - a malformed or negative
    # Upload-Offset/Upload-Length used to reach a bare int() and surface as
    # an unhandled 500 (or, negative, as a nonsense length bound).
    if not re.fullmatch(r"[0-9]+", value.strip()):
        raise HTTPException(status_code=400, detail=f"Malformed {name} header")
    return int(value)


def _hash_file(path: Path) -> str:
    # Re-reads the whole finished file once on completion rather than
    # carrying hashlib state across separate part requests/worker restarts
    # - that state isn't reliably serializable, and a full local-disk
    # read+hash is seconds even for a 10GiB file, negligible next to a
    # transfer that by definition takes minutes-to-hours over the network.
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# Open-ended (bytes=N-) and closed (bytes=N-M) forms. A resumed download
# always wants "give me from N onward"; the closed form additionally
# bounds the response to one part-sized piece so a flat per-request
# timeout on the client's side is actually correct (see rustdrop_transfer.rs
# / the resumable-transfer redesign).
_RANGE_RE = re.compile(r"^bytes=(\d+)-(\d*)$")


def _parse_range(range_header: str | None) -> tuple[int, int | None]:
    if not range_header:
        return 0, None
    match = _RANGE_RE.match(range_header.strip())
    if not match:
        raise HTTPException(status_code=400, detail="Malformed Range header")
    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) else None
    if end is not None and end < start:
        raise HTTPException(status_code=400, detail="Malformed Range header")
    return start, end


async def _copy_body_to_file(request: Request, f) -> int:
    written = 0
    async for chunk in request.stream():
        f.write(chunk)
        written += len(chunk)
    return written


async def _read_body_bytes(request: Request, max_bytes: int | None = None) -> bytes:
    # max_bytes is enforced on the bytes actually received, not on
    # Content-Length - a chunked body has none, and a part that would run
    # past the declared Upload-Length is cut off here rather than buffered
    # whole first.
    chunks = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if max_bytes is not None and received > max_bytes:
            raise HTTPException(status_code=413, detail="part runs past declared Upload-Length")
        chunks.append(chunk)
    return b"".join(chunks)


def _do_locked_upload(key: str, offset: int, body: bytes, upload_length: int | None) -> dict:
    # Runs on a worker thread via asyncio.to_thread - fcntl.flock and all
    # disk I/O for this part happen here, never on the event loop, so a
    # contended lock can no longer stall every other request this process is
    # serving. Finalization (hash/sidecar-write/marker-removal) now happens
    # inside this same locked call for the part that completes the upload,
    # not after the lock has already been released - a crash between "wrote
    # the last byte" and "removed the marker" used to leave a fully-correct
    # file permanently misreported as still-uploading; it can't now, since
    # either the whole locked block finishes or none of it does.
    path = _blob_path(key)
    with _blob_lock(key):
        current_size = _current_blob_size(key)
        if offset != current_size:
            return {"conflict": True, "current_offset": current_size}

        if offset == 0:
            if upload_length is None:
                raise HTTPException(status_code=400, detail="Upload-Length required at offset 0")
            declared_length = upload_length
        else:
            existing_marker = _read_uploading_marker(key)
            if existing_marker is None:
                raise HTTPException(status_code=410, detail="upload session no longer exists")
            declared_length = existing_marker["upload_length"]

        new_offset = offset + len(body)
        if new_offset > declared_length:
            # Checked before anything touches disk (marker included) - an
            # overshooting part used to be written first and rejected after,
            # leaving bytes past the declared length on disk. Refused whole
            # now, so the already-confirmed prefix stays exactly as it was
            # and the caller can resume from it.
            raise HTTPException(status_code=413, detail="part runs past declared Upload-Length")

        if offset == 0:
            _write_uploading_marker(key, upload_length=declared_length)
            mode = "wb"
        else:
            mode = "r+b"

        with open(path, mode) as f:
            f.seek(offset)
            f.write(body)

        if new_offset == declared_length:
            digest = _hash_file(path)
            _sha256_sidecar_path(key).write_text(digest)
            _marker_path(key).unlink(missing_ok=True)
            return {"conflict": False, "new_offset": new_offset, "complete": True, "sha256": digest}

        return {"conflict": False, "new_offset": new_offset, "complete": False}


@app.put("/blobs/{key}")
async def upload_blob(
    key: str,
    request: Request,
    authorization: str | None = Header(default=None),
    upload_offset: str | None = Header(default=None),
    upload_length: str | None = Header(default=None),
):
    _check_auth(authorization)
    path = _blob_path(key)

    if upload_offset is None:
        # Legacy path: whole body in one request, truncate. The marker now
        # carries real JSON (via _write_uploading_marker, same as the
        # resumable path below) instead of an empty touch()'d file -
        # _read_uploading_marker's json.loads() failed on the empty file and
        # silently swallowed that as "no marker", which head_blob reads as
        # "upload complete" (see the `if marker is not None` branch below) -
        # a HEAD during a legacy in-progress upload used to misreport done
        # with no sha256 yet. upload_length isn't always known for a legacy
        # caller (Upload-Length is a resumable-protocol header, but some
        # single-shot callers do send it); 0 is just a placeholder signaling
        # "unknown" when absent, not a real declared size - never compared
        # against for the legacy path's own completion logic below.
        declared_length = (
            _parse_length_header(upload_length, "Upload-Length") if upload_length is not None else 0
        )
        _write_uploading_marker(key, upload_length=declared_length)
        # A digest left over from an earlier upload of this key must not be
        # served (or read by tail_follow as "finished cleanly") for this one.
        _sha256_sidecar_path(key).unlink(missing_ok=True)
        hasher = hashlib.sha256()
        try:
            with open(path, "wb") as f:
                async for chunk in request.stream():
                    f.write(chunk)
                    hasher.update(chunk)
            digest = hasher.hexdigest()
            # Sidecar before marker removal, same order as the resumable
            # path's finalization - "no marker" must never be observable
            # before the digest exists.
            _sha256_sidecar_path(key).write_text(digest)
        except BaseException:
            # Caller disconnected mid-body (RDS aborts the relay when a
            # client overruns its size limit or drops), disk full, or
            # cancelled: discard the partial blob along with the marker.
            # Removing only the marker used to leave "blob present, no
            # marker", which head_blob/download_blob read as a finished
            # upload. A legacy upload can't be resumed anyway - a retry
            # starts over at byte 0.
            _discard_upload(key)
            raise
        _marker_path(key).unlink(missing_ok=True)
        return {"bytes_written": path.stat().st_size, "sha256": digest}

    # Resumable mode: Upload-Offset present. Body is read off the network
    # (the slow part) before touching the lock at all, so the lock is only
    # ever held for the fast, in-memory-to-disk part - see _do_locked_upload.
    offset = _parse_length_header(upload_offset, "Upload-Offset")
    declared_length = (
        _parse_length_header(upload_length, "Upload-Length") if upload_length is not None else None
    )

    # Most bytes this part may carry without running past the declared
    # total - known from the Upload-Length header at offset 0, else from the
    # in-progress marker. Read unlocked, so advisory only: it lets an
    # overshooting part be refused before its body is read (Content-Length)
    # or cut off while it streams (chunked/short-lying), while
    # _do_locked_upload repeats the authoritative check before writing.
    # None (no marker past offset 0) skips the early check entirely, so
    # that case still gets the locked path's own 409/410 exactly as before.
    if offset == 0:
        bound_length = declared_length
    else:
        marker_state = _read_uploading_marker(key)
        bound_length = marker_state.get("upload_length") if marker_state is not None else None
    max_part_bytes = max(bound_length - offset, 0) if isinstance(bound_length, int) else None
    if max_part_bytes is not None:
        content_length = request.headers.get("content-length")
        if content_length is not None and re.fullmatch(r"[0-9]+", content_length.strip()):
            if int(content_length) > max_part_bytes:
                raise HTTPException(status_code=413, detail="part runs past declared Upload-Length")

    body = await _read_body_bytes(request, max_part_bytes)
    result = await asyncio.to_thread(_do_locked_upload, key, offset, body, declared_length)

    if result["conflict"]:
        return JSONResponse(
            status_code=409,
            headers={"Upload-Offset": str(result["current_offset"])},
            content={"detail": "offset mismatch", "current_offset": result["current_offset"]},
        )

    if result["complete"]:
        return Response(headers={
            "Upload-Offset": str(result["new_offset"]),
            "X-Upload-Complete": "true",
            "X-Content-SHA256": result["sha256"],
        })
    return Response(headers={"Upload-Offset": str(result["new_offset"]), "X-Upload-Complete": "false"})


@app.head("/blobs/{key}")
async def head_blob(key: str, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    marker = _read_uploading_marker(key)
    if not _blob_path(key).exists() and marker is None:
        raise HTTPException(status_code=404, detail="not found")

    if marker is not None:
        return Response(headers={
            "Upload-Offset": str(_current_blob_size(key)),
            "Upload-Length": str(marker["upload_length"]),
            "X-Upload-Complete": "false",
        })
    sha256_path = _sha256_sidecar_path(key)
    return Response(headers={
        "Upload-Offset": str(_current_blob_size(key)),
        "X-Upload-Complete": "true",
        "X-Content-SHA256": sha256_path.read_text().strip() if sha256_path.exists() else "",
    })


@app.get("/blobs/{key}")
async def download_blob(
    key: str,
    authorization: str | None = Header(default=None),
    range: str | None = Header(default=None),
):
    _check_auth(authorization)
    path = _blob_path(key)
    marker = _marker_path(key)
    sha256_path = _sha256_sidecar_path(key)

    if not path.exists() and not marker.exists():
        raise HTTPException(status_code=404, detail="not found")

    start, end = _parse_range(range)
    current_size = path.stat().st_size if path.exists() else 0
    if start > current_size:
        # Resuming past what the file actually has (should only happen if a
        # client's own bookkeeping is wrong) - can't satisfy this range.
        raise HTTPException(
            status_code=416,
            detail="Range start beyond current size",
            headers={"Content-Range": f"bytes */{current_size}"},
        )

    async def tail_follow(from_position: int, until_position: int | None):
        position = from_position
        idle_seconds = 0.0
        while True:
            if until_position is not None and position > until_position:
                break
            if path.exists():
                size = path.stat().st_size
                cap = size if until_position is None else min(size, until_position + 1)
                if cap > position:
                    with open(path, "rb") as f:
                        f.seek(position)
                        chunk = f.read(cap - position)
                    position += len(chunk)
                    idle_seconds = 0.0
                    yield chunk
                    if until_position is not None and position > until_position:
                        break
                    continue
            if not marker.exists():
                if not sha256_path.exists():
                    # Marker gone with no digest behind it: the upload
                    # failed or the blob was deleted mid-follow (both
                    # upload paths write the sidecar before removing the
                    # marker). Abort the response instead of ending it
                    # cleanly, so the caller sees a broken transfer, not a
                    # short file that looks complete.
                    raise RuntimeError(f"upload for blob {key} ended without completing")
                # Upload finished and we've now read everything it wrote.
                break
            await asyncio.sleep(TAIL_POLL_INTERVAL_SECONDS)
            idle_seconds += TAIL_POLL_INTERVAL_SECONDS
            if idle_seconds > TAIL_IDLE_TIMEOUT_SECONDS:
                break

    # Only meaningful once the sidecar exists (written after upload_blob
    # finishes) - absent while still uploading, since the digest isn't known
    # until every byte has been hashed. The client uses this to verify the
    # fully reassembled file, whether fetched in one shot or resumed across
    # several Range requests.
    extra_headers = {}
    if sha256_path.exists():
        extra_headers["X-Content-SHA256"] = sha256_path.read_text().strip()

    if range is None:
        return StreamingResponse(
            tail_follow(0, None), media_type="application/octet-stream", headers=extra_headers
        )

    # 206 for any Range request, even bytes=0- - a resuming client asks with
    # a Range header either way, and this confirms the server understood it
    # as a range rather than silently falling back to a full 200 response.
    # total_or_star: the real total once upload is complete (marker gone),
    # else "*" - still-growing content has no known final size yet.
    total = str(current_size) if not marker.exists() else "*"
    last_known = end if end is not None else (max(start, current_size - 1) if current_size else start)
    return StreamingResponse(
        tail_follow(start, end),
        status_code=206,
        media_type="application/octet-stream",
        headers={
            "Content-Range": f"bytes {start}-{last_known}/{total}",
            "Accept-Ranges": "bytes",
            **extra_headers,
        },
    )


@app.delete("/blobs/{key}")
async def delete_blob(key: str, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    _blob_path(key).unlink(missing_ok=True)
    _marker_path(key).unlink(missing_ok=True)
    _sha256_sidecar_path(key).unlink(missing_ok=True)
    _lock_path(key).unlink(missing_ok=True)
    return {"deleted": True}


@app.get("/healthz")
async def healthz():
    return {"ok": True}
