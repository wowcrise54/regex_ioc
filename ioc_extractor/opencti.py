"""Импорт IoC в OpenCTI (GraphQL API) в отдельный черновик (Draft workspace).

Черновик создаётся мутацией draftWorkspaceAdd; все последующие запросы с заголовком
`opencti-draft-id` выполняются в контексте черновика и не попадают в основную базу,
пока аналитик не подтвердит (Validate) черновик в интерфейсе OpenCTI
(Data -> Import -> Drafts). Требуется OpenCTI 6.5+.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import requests

from .extractor import IoC

HASH_ALGORITHMS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}

_OBSERVABLE_ADD = """
mutation IoCObservableAdd($type: String!, $score: Int, $description: String, $createIndicator: Boolean,
  $DomainName: DomainNameAddInput, $IPv4Addr: IPv4AddrAddInput, $IPv6Addr: IPv6AddrAddInput,
  $Url: UrlAddInput, $EmailAddr: EmailAddrAddInput, $StixFile: StixFileAddInput) {
  stixCyberObservableAdd(type: $type, x_opencti_score: $score, x_opencti_description: $description,
    createIndicator: $createIndicator, DomainName: $DomainName, IPv4Addr: $IPv4Addr,
    IPv6Addr: $IPv6Addr, Url: $Url, EmailAddr: $EmailAddr, StixFile: $StixFile) {
    id
  }
}
"""

_DRAFT_ADD = """
mutation IoCDraftAdd($input: DraftWorkspaceAddInput!) {
  draftWorkspaceAdd(input: $input) { id name }
}
"""

_REPORT_ADD = """
mutation IoCReportAdd($input: ReportAddInput!) {
  reportAdd(input: $input) { id }
}
"""


class OpenCTIError(Exception):
    pass


@dataclass
class ImportResult:
    draft_id: str
    draft_name: str
    created: int = 0
    report_id: str = ""
    errors: list[str] = field(default_factory=list)


def observable_variables(ioc: IoC) -> dict:
    """Переменные мутации stixCyberObservableAdd для конкретного IoC."""
    if ioc.type == "domain":
        return {"type": "Domain-Name", "DomainName": {"value": ioc.value}}
    if ioc.type == "url":
        return {"type": "Url", "Url": {"value": ioc.value}}
    if ioc.type == "email":
        return {"type": "Email-Addr", "EmailAddr": {"value": ioc.value}}
    if ioc.type == "ip":
        if ioc.subtype == "ipv6":
            return {"type": "IPv6-Addr", "IPv6Addr": {"value": ioc.value}}
        return {"type": "IPv4-Addr", "IPv4Addr": {"value": ioc.value}}
    if ioc.type == "hash":
        algorithm = HASH_ALGORITHMS[ioc.subtype]
        return {"type": "StixFile", "StixFile": {"hashes": [{"algorithm": algorithm, "hash": ioc.value}]}}
    raise ValueError(f"Неизвестный тип IoC: {ioc.type}")


class OpenCTIClient:
    def __init__(self, url: str, token: str, verify_ssl: bool = True, timeout: int = 60):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl
        self.timeout = timeout

    def query(self, query: str, variables: dict | None = None, draft_id: str | None = None) -> dict:
        headers = {"opencti-draft-id": draft_id} if draft_id else None
        try:
            r = self.session.post(f"{self.url}/graphql", json={"query": query, "variables": variables or {}},
                                  headers=headers, timeout=self.timeout)
        except requests.RequestException as e:
            raise OpenCTIError(f"Ошибка соединения: {e}") from e
        if r.status_code in (401, 403):
            raise OpenCTIError("Доступ запрещён — проверьте API-токен")
        try:
            payload = r.json()
        except ValueError as e:
            raise OpenCTIError(f"Некорректный ответ сервера (HTTP {r.status_code})") from e
        if payload.get("errors"):
            err = payload["errors"][0]
            msg = err.get("message", "")
            reason = (err.get("extensions") or {}).get("data", {}).get("reason")
            raise OpenCTIError(f"{msg}: {reason}" if reason else msg)
        return payload.get("data") or {}

    def version(self) -> str:
        return self.query("query { about { version } }")["about"]["version"]

    def create_draft(self, name: str, description: str = "") -> str:
        data = self.query(_DRAFT_ADD, {"input": {"name": name, "description": description}})
        return data["draftWorkspaceAdd"]["id"]

    def create_observable(self, ioc: IoC, draft_id: str, score: int | None,
                          create_indicator: bool, description: str = "") -> str:
        variables = observable_variables(ioc)
        variables.update(score=score, createIndicator=create_indicator, description=description or None)
        data = self.query(_OBSERVABLE_ADD, variables, draft_id)
        return data["stixCyberObservableAdd"]["id"]

    def create_report(self, name: str, object_ids: list[str], draft_id: str, description: str = "") -> str:
        report = {
            "name": name,
            "description": description,
            "published": datetime.now(timezone.utc).isoformat(),
            "report_types": ["threat-report"],
            "objects": object_ids,
        }
        return self.query(_REPORT_ADD, {"input": report}, draft_id)["reportAdd"]["id"]

    def import_iocs(self, iocs: list[IoC], draft_name: str, score: int | None = 50,
                    create_indicator: bool = True, create_report: bool = True,
                    description: str = "",
                    progress: Callable[[int, int], None] | None = None,
                    cancelled: Callable[[], bool] | None = None) -> ImportResult:
        draft_id = self.create_draft(draft_name, description)
        result = ImportResult(draft_id, draft_name)
        ids = []
        for n, ioc in enumerate(iocs, 1):
            if cancelled and cancelled():
                result.errors.append("Импорт прерван пользователем")
                break
            try:
                ids.append(self.create_observable(ioc, draft_id, score, create_indicator, description))
                result.created += 1
            except OpenCTIError as e:
                result.errors.append(f"{ioc.value}: {e}")
            if progress:
                progress(n, len(iocs))
        if create_report and ids:
            try:
                result.report_id = self.create_report(draft_name, ids, draft_id, description)
            except OpenCTIError as e:
                result.errors.append(f"Отчёт (Report) не создан: {e}")
        return result
