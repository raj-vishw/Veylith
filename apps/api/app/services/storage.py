"""Private file storage for evidence uploads and generated reports.

Files live under STORAGE_DIR/<organization>/<random name>. Callers never choose the stored name,
and nothing here is served directly: every download goes through an authorised API route."""

import hashlib
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile

from ..config import get_settings

# extension -> (content type served back, magic-byte prefixes or None for text)
ALLOWED_UPLOADS: dict[str, tuple[str, tuple[bytes, ...] | None]] = {
    ".pdf": ("application/pdf", (b"%PDF-",)),
    ".png": ("image/png", (b"\x89PNG\r\n\x1a\n",)),
    ".jpg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".jpeg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".txt": ("text/plain", None),
    ".log": ("text/plain", None),
    ".md": ("text/plain", None),
    ".csv": ("text/csv", None),
    ".json": ("application/json", None),
}


class Storage:
    def __init__(self, root: str | None = None):
        self.root = Path(root or get_settings().storage_dir).resolve()

    def _path(self, org_id, key: str) -> Path:
        if not key.isalnum():
            raise ValueError("invalid storage key")
        path = (self.root / str(org_id) / key).resolve()
        if self.root not in path.parents:
            raise ValueError("path escapes storage root")
        return path

    def put(self, org_id, data: bytes) -> tuple[str, str]:
        key = uuid.uuid4().hex
        path = self._path(org_id, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return key, hashlib.sha256(data).hexdigest()

    def path(self, org_id, key: str) -> Path:
        path = self._path(org_id, key)
        if not path.is_file():
            raise FileNotFoundError(key)
        return path

    def read(self, org_id, key: str) -> bytes:
        return self.path(org_id, key).read_bytes()

    def delete(self, org_id, key: str) -> None:
        try:
            self._path(org_id, key).unlink(missing_ok=True)
        except ValueError:
            pass


def storage() -> Storage:
    return Storage()


async def read_upload(file: UploadFile) -> tuple[bytes, str, str]:
    """Validates size, extension allowlist and content signature. Returns (data, content_type, safe_filename)."""
    s = get_settings()
    name = Path(file.filename or "").name
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_UPLOADS:
        raise HTTPException(status_code=415, detail=f"File type not allowed. Allowed: {', '.join(sorted(ALLOWED_UPLOADS))}")
    chunks, size = [], 0
    while chunk := await file.read(64 * 1024):
        size += len(chunk)
        if size > s.max_upload_bytes:
            raise HTTPException(status_code=413, detail="File too large")
        chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        raise HTTPException(status_code=422, detail="File is empty")
    content_type, magics = ALLOWED_UPLOADS[ext]
    if magics is not None:
        if not data.startswith(magics):
            raise HTTPException(status_code=415, detail="File content does not match its extension")
    else:
        if b"\x00" in data:
            raise HTTPException(status_code=415, detail="File content does not match its extension")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=415, detail="Text files must be UTF-8")
    return data, content_type, name[:300]
