"""Elasticsearch backend wrapper.

Owns the client and the read-only contract: only search and count calls
are ever made. Anything else on the client is out of reach for the tools.
"""

from __future__ import annotations

from typing import Any

from .config import Config
from .errors import BackendError


class EsBackend:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._client = None

    def _get_client(self):
        if self._client is None:
            from elasticsearch import Elasticsearch

            kwargs: dict[str, Any] = {
                "hosts": [self.cfg.es_url],
                "request_timeout": self.cfg.request_timeout_s,
                "max_retries": 1,
                "retry_on_timeout": False,
            }
            if self.cfg.es_username and self.cfg.es_password:
                kwargs["basic_auth"] = (self.cfg.es_username, self.cfg.es_password)
            if self.cfg.es_ca_cert:
                kwargs["ca_certs"] = self.cfg.es_ca_cert
                kwargs["verify_certs"] = True
            else:
                # Lab/dev stacks run with security disabled on localhost.
                kwargs["verify_certs"] = False
            self._client = Elasticsearch(**kwargs)
        return self._client

    def search(self, index: str, body: dict) -> dict:
        client = self._get_client()
        try:
            resp = client.search(index=index, body=body)
        except Exception as exc:  # elasticsearch raises many types; normalize
            raise BackendError(f"elasticsearch search failed: {exc}") from exc
        return dict(resp)

    def index_exists(self, index: str) -> bool:
        client = self._get_client()
        try:
            return bool(client.indices.exists(index=index))
        except Exception as exc:
            raise BackendError(f"elasticsearch reachability check failed: {exc}") from exc

    def count(self, index: str, query: dict) -> int:
        client = self._get_client()
        try:
            resp = client.count(index=index, body={"query": query})
        except Exception as exc:
            raise BackendError(f"elasticsearch count failed: {exc}") from exc
        return int(resp.get("count", 0))

    def mget(self, index: str, ids: list[str]) -> list[dict]:
        client = self._get_client()
        try:
            resp = client.mget(index=index, body={"ids": ids})
        except Exception as exc:
            raise BackendError(f"elasticsearch mget failed: {exc}") from exc
        return [
            {"_index": d.get("_index"), "_id": d.get("_id"), "_source": d.get("_source"), "found": d.get("found", False)}
            for d in resp.get("docs", [])
        ]

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
