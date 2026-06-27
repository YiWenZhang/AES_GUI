# -*- coding: utf-8 -*-
from dataclasses import dataclass
import hashlib
import os


@dataclass(frozen=True)
class FileHashResult:
    path: str
    sha256: str
    size: int


class IntegrityService:
    def sha256_file(self, path: str) -> FileHashResult:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"文件不存在: {path}")

        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return FileHashResult(
            path=os.path.abspath(path),
            sha256=digest.hexdigest(),
            size=os.path.getsize(path),
        )

    def verify_sha256(self, path: str, expected_hash: str) -> bool:
        expected = expected_hash.strip().lower().replace(" ", "")
        if len(expected) != 64:
            return False
        return self.sha256_file(path).sha256 == expected
