# RustDrop Storage

A minimal, single-purpose blob store backing **RustDrop**, the managed file-drop feature in
[rustdesk-managed-client](https://github.com/MAGA-Brad/rustdesk-managed-client) ("RDC") and
[rustdesk-managed-directory-api](https://github.com/MAGA-Brad/rustdesk-managed-directory-api)
("RDS").

This service knows nothing about device identity, users, or RustDesk itself — it only knows "some
caller holding the shared secret asked for blob X." All authorization (does this sender own the
drop, is this recipient the addressee) happens in RDS before a request ever reaches this service.
It's meant to run on an internal-only network segment reachable only by RDS — never exposed
directly to clients or the public internet.

## What it does

- **Resumable uploads** — `PUT /blobs/{key}` accepts either a whole body in one request (legacy,
  still supported) or a resumable series of offset-addressed parts via `Upload-Offset` /
  `Upload-Length` headers, in the style of the [tus.io](https://tus.io) protocol. A part landing at
  an unexpected offset returns `409` with the server's real current offset so the caller can
  resync instead of blindly retrying.
- **Resumable, tail-following downloads** — `GET /blobs/{key}` supports HTTP `Range` requests,
  including against a blob that's still being uploaded: a download can start reading bytes that
  already landed and keep following as more arrive, rather than waiting for the whole transfer to
  finish first.
- **Integrity verification** — a SHA-256 digest is computed once, when an upload completes, and
  served back via `X-Content-SHA256` on both the completing upload response and any subsequent
  download, so the caller can verify the fully reassembled file end to end.
- **Concurrency-safe writes** — per-blob file locking (via `flock`) makes concurrent or retried
  part uploads for the same key safe, even though RustDrop's own client never intentionally
  overlaps two part uploads for one drop.

## API

| Method | Path | Purpose |
|---|---|---|
| `PUT` | `/blobs/{key}` | Upload a blob, whole or as a resumable part |
| `HEAD` | `/blobs/{key}` | Query current upload progress / completion state |
| `GET` | `/blobs/{key}` | Download a blob, optionally by `Range`, optionally mid-upload |
| `DELETE` | `/blobs/{key}` | Remove a blob and its associated metadata |
| `GET` | `/healthz` | Liveness check |

Every request (other than `/healthz`) requires `Authorization: Bearer <RUSTDROP_STORAGE_SECRET>`.
The service refuses to start if `RUSTDROP_STORAGE_SECRET` is unset or shorter than 16 characters.
FastAPI's interactive docs (`/docs`, `/redoc`, `/openapi.json`) are disabled.

## Running it

```sh
pip install -r requirements.in
cp .env.example .env   # fill in RUSTDROP_STORAGE_SECRET
uvicorn app:app --host 0.0.0.0 --port 8443 --env-file .env \
  --ssl-keyfile /opt/rustdrop-storage/tls/key.pem \
  --ssl-certfile /opt/rustdrop-storage/tls/cert.pem
```

Serve it over TLS as above (the caller should pin that certificate), and bind `--host` to the
internal interface the caller reaches it on rather than `0.0.0.0` where you can. Under systemd, an
`EnvironmentFile=` pointing at the same `.env` works in place of `--env-file`.

Blobs are written under `/mnt/rustdrop-storage/blobs` — point that at whatever storage (ideally an
encrypted-at-rest volume) you want blobs to actually live on.

## Status

Actively developed alongside RustDrop in RDC/RDS — expect the storage API to evolve as the
resumable-transfer design on the client side is finished and hardened.

No changes were needed for RDC builds 29 through 34. Since build 29 the client compresses
compressible files chunk by chunk (zstd) before encrypting them when the recipient supports that,
and caps parts at 90 MiB; this service still stores only opaque ciphertext and never needs to
know.
