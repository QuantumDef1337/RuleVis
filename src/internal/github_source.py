"""
GitHub rule source client.

Pulls Wazuh rule XML files out of a GitHub repository (public or private) into
a local cache directory, mirrored the same way wazuh_api.py mirrors a Wazuh
manager's rule files — so the rest of the pipeline (generator/analyzer) can
treat a GitHub source exactly like a local directory.

Auth is optional: no token works for public repos; a personal access token
(classic or fine-grained) is used for private repos via the same Contents API
call, so one code path covers both cases.
"""

import base64
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final, Optional

from internal import crypto

ENCODING: Final[str] = "utf-8"
TIMEOUT: Final[int] = 30
API_BASE: Final[str] = "https://api.github.com"


class GithubApiError(Exception):
    ...


class GithubClient:
    def __init__(self, repo: str, branch: str = "main", path: str = "",
                 token: Optional[str] = None) -> None:
        self.repo = repo.strip().strip("/")
        self.branch = branch.strip() or "main"
        self.path = path.strip().strip("/")
        self.token = token or None

    # ---------- low-level ----------
    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json",
                   "User-Agent": "rulevis"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    def _get(self, path: str) -> bytes:
        req = urllib.request.Request(f"{API_BASE}{path}", headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode(ENCODING, errors="replace")[:500]
            hint = " (private repo? add a token)" if e.code in (401, 404) and not self.token else ""
            raise GithubApiError(f"HTTP {e.code} on {path}{hint}: {body}") from e
        except (urllib.error.URLError, OSError) as e:
            raise GithubApiError(f"Cannot reach GitHub: {e}") from e

    def _get_json(self, path: str) -> Any:
        return json.loads(self._get(path).decode(ENCODING))

    # ---------- high-level ----------
    def info(self) -> dict[str, Any]:
        """Basic repo info; also serves as a connection test."""
        data = self._get_json(f"/repos/{self.repo}")
        return {
            "full_name": data.get("full_name"),
            "private": data.get("private"),
            "default_branch": data.get("default_branch"),
        }

    def list_xml_files(self) -> list[str]:
        """All .xml file paths in the repo tree under the configured path prefix."""
        qs = urllib.parse.urlencode({"recursive": "1"})
        data = self._get_json(f"/repos/{self.repo}/git/trees/{urllib.parse.quote(self.branch)}?{qs}")
        if data.get("truncated"):
            logging.warning(f"GitHub tree for {self.repo}@{self.branch} was truncated by the API; "
                            "some files may be missing. Narrow the configured path to avoid this.")
        entries = data.get("tree", [])
        prefix = f"{self.path}/" if self.path else ""
        return [e["path"] for e in entries
                if e.get("type") == "blob" and e["path"].lower().endswith(".xml")
                and e["path"].startswith(prefix)]

    def fetch_file(self, path: str) -> str:
        qs = urllib.parse.urlencode({"ref": self.branch})
        data = self._get_json(f"/repos/{self.repo}/contents/{urllib.parse.quote(path)}?{qs}")
        content = data.get("content", "")
        encoding = data.get("encoding", "base64")
        if encoding != "base64":
            raise GithubApiError(f"Unexpected content encoding '{encoding}' for {path}")
        return base64.b64decode(content).decode(ENCODING, errors="replace")

    def download_ruleset(self, target_root: str, source_id: str) -> dict[str, Any]:
        """
        Downloads .xml files into target_root, preserving their path relative
        to the configured path prefix. Returns a summary. `target_root` is
        the already tenant-scoped cache directory
        (config.cache_dir(tenant_id, f"gh-{source_id}")).
        """
        paths = self.list_xml_files()
        downloaded, errors = 0, []
        for p in paths:
            rel = p[len(self.path) + 1:] if self.path else p
            try:
                content = self.fetch_file(p)
                out_path = os.path.join(target_root, *rel.split("/"))
                os.makedirs(os.path.dirname(out_path) or target_root, exist_ok=True)
                with open(out_path, "w", encoding=ENCODING) as fh:
                    fh.write(content)
                downloaded += 1
            except GithubApiError as e:
                logging.error(f"Failed to fetch {p}: {e}")
                errors.append({"file": p, "error": str(e)})
        logging.info(f"GitHub source {source_id}: downloaded {downloaded} rule files to {target_root}")
        return {
            "source_id": source_id,
            "cache_path": target_root,
            "downloaded": downloaded,
            "errors": errors,
            "total": len(paths),
        }


def client_from_config(source: dict[str, Any]) -> GithubClient:
    # Stored encrypted at rest (see config.py's upsert_github_source /
    # internal.crypto) — decrypted here, at the one place it's actually used.
    token = crypto.decrypt(source.get("token") or "")
    return GithubClient(
        repo=source["repo"],
        branch=source.get("branch") or "main",
        path=source.get("path", ""),
        token=token or None,
    )
