"""
Wazuh Manager API client for live rule fetching.

Authenticates with basic auth to obtain a JWT, lists rule files, downloads
raw XML into a per-manager local cache directory, so the rest of the pipeline
(generator/analyzer) can treat a live manager exactly like a local directory.

Supports any number of managers (batch analysis across environments).
"""

import base64
import json
import logging
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final, Optional

from internal import crypto

ENCODING: Final[str] = "utf-8"
TIMEOUT: Final[int] = 30


class WazuhApiError(Exception):
    ...


class WazuhClient:
    def __init__(self, url: str, username: str, password: str,
                 verify_tls: bool = False) -> None:
        self.base_url = url.rstrip("/")
        self.username = username
        self.password = password
        self._token: Optional[str] = None
        self._ctx: Optional[ssl.SSLContext] = None
        if not verify_tls:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    # ---------- low-level ----------
    def _request(self, method: str, path: str, headers: dict[str, str],
                 data: Optional[bytes] = None) -> bytes:
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self._ctx) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode(ENCODING, errors="replace")[:500]
            raise WazuhApiError(f"HTTP {e.code} on {path}: {body}") from e
        except (urllib.error.URLError, OSError) as e:
            raise WazuhApiError(f"Cannot reach {self.base_url}: {e}") from e

    def authenticate(self) -> str:
        creds = base64.b64encode(
            f"{self.username}:{self.password}".encode(ENCODING)).decode("ascii")
        raw = self._request(
            "POST", "/security/user/authenticate?raw=true",
            headers={"Authorization": f"Basic {creds}"})
        self._token = raw.decode(ENCODING).strip()
        if not self._token or "{" in self._token[:1]:
            raise WazuhApiError("Authentication failed: unexpected token response")
        return self._token

    def _get(self, path: str) -> bytes:
        if not self._token:
            self.authenticate()
        try:
            return self._request(
                "GET", path, headers={"Authorization": f"Bearer {self._token}"})
        except WazuhApiError as e:
            # JWT expires after ~15 minutes; retry once with a fresh token
            if "HTTP 401" in str(e):
                self.authenticate()
                return self._request(
                    "GET", path, headers={"Authorization": f"Bearer {self._token}"})
            raise

    def _get_json(self, path: str) -> dict[str, Any]:
        return json.loads(self._get(path).decode(ENCODING))

    # ---------- high-level ----------
    def info(self) -> dict[str, Any]:
        """Basic manager info; also serves as a connection test."""
        data = self._get_json("/manager/info")
        items = data.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    def list_rule_files(self) -> list[dict[str, Any]]:
        """All rule files with their relative dirname and status."""
        files: list[dict[str, Any]] = []
        offset = 0
        while True:
            data = self._get_json(f"/rules/files?limit=500&offset={offset}")
            batch = data.get("data", {}).get("affected_items", [])
            files.extend(batch)
            total = data.get("data", {}).get("total_affected_items", 0)
            offset += len(batch)
            if offset >= total or not batch:
                break
        return files

    def fetch_rule_file(self, filename: str, relative_dirname: str) -> str:
        qs = urllib.parse.urlencode(
            {"raw": "true", "relative_dirname": relative_dirname})
        return self._get(f"/rules/files/{urllib.parse.quote(filename)}?{qs}").decode(
            ENCODING, errors="replace")

    def download_ruleset(self, target_root: str, manager_id: str,
                         include_builtin: bool = True,
                         include_custom: bool = True) -> dict[str, Any]:
        """
        Downloads rule files into target_root/<relative_dirname>/, mirroring
        the manager layout. Returns a summary. `target_root` is the already
        tenant-scoped cache directory (config.cache_dir(tenant_id, manager_id)).
        """
        files = self.list_rule_files()
        downloaded, skipped, errors = 0, 0, []
        for f in files:
            rel = f.get("relative_dirname", "") or ""
            is_builtin = rel.startswith("ruleset")
            if (is_builtin and not include_builtin) or (not is_builtin and not include_custom):
                skipped += 1
                continue
            filename = f.get("filename", "")
            if not filename:
                continue
            try:
                content = self.fetch_rule_file(filename, rel)
                out_dir = os.path.join(target_root, *rel.split("/"))
                os.makedirs(out_dir, exist_ok=True)
                with open(os.path.join(out_dir, filename), "w", encoding=ENCODING) as fh:
                    fh.write(content)
                downloaded += 1
            except WazuhApiError as e:
                logging.error(f"Failed to fetch {rel}/{filename}: {e}")
                errors.append({"file": f"{rel}/{filename}", "error": str(e)})
        logging.info(
            f"Manager {manager_id}: downloaded {downloaded} rule files to {target_root}")
        return {
            "manager_id": manager_id,
            "cache_path": target_root,
            "downloaded": downloaded,
            "skipped": skipped,
            "errors": errors,
            "total": len(files),
        }


def client_from_config(manager: dict[str, Any]) -> WazuhClient:
    return WazuhClient(
        url=manager["url"],
        username=manager.get("username", ""),
        # Stored encrypted at rest (see config.py's upsert_manager /
        # internal.crypto) — decrypted here, at the one place it's actually
        # used, rather than carrying plaintext through the rest of the app.
        password=crypto.decrypt(manager.get("password", "")),
        verify_tls=bool(manager.get("verify_tls", False)),
    )
