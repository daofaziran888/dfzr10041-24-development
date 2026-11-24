"""多源日志的双方授权共享去重与采样归并。

本模块实现题目要求的完整领域规则：

1. ``来源共享去重范围``（:class:`SharingScope`）必须由两个来源经双方凭证
   批准（:class:`SourceCredential` / :class:`SharingAgreement`）后才生效；
   只有明确同组的两个来源可以折叠相同请求码。无关来源（例如丙/C）始终独立。
2. :func:`deduplicate` 负责归组，:func:`sample` 负责实际领取各组唯一代表；
   每个样本通过 :class:`LineRef` 保留各来源可核对的原行位置（来源、行号、
   校验值、原文）。
3. 授权冲突时按“选定的双方凭证”处理；共享权限决定能否跨来源读取指纹/日志，
   未获许可的归并抛出 :class:`UnauthorizedMergeError`（越权）。
4. 共享键相同但请求内容矛盾时，不任选一条原行当代表，而是保留全部来源证据
   并隔离为 :class:`Dispute`。
5. 任一方撤销后：已交付样本保留原权限依据；新调查重新拆成独立来源。
6. 交付/确认采用两阶段与幂等恢复：采样侧已交付但授权侧未收到确认时进入
   “中断/待核清”状态；:meth:`SamplingOffice.recover` 先核对原交付 manifest，
   绝不按撤销后的新分组重发同一原行。

模块仅依赖标准库，可直接 ``python tests/test_source_sharing.py`` 运行。
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable


# ---------------------------------------------------------------------------
# 来源别名：题目中的 A/B/C 与 甲/乙/丙 是同一组三个来源
# ---------------------------------------------------------------------------

#: 已知来源别名归一化表（key 会做 strip + lower 处理，中文原样保留）。
SOURCE_ALIASES: dict[str, str] = {
    "a": "A", "src-a": "A", "source-a": "A", "jia": "A", "甲": "A",
    "b": "B", "src-b": "B", "source-b": "B", "yi": "B", "乙": "B",
    "c": "C", "src-c": "C", "source-c": "C", "bing": "C", "丙": "C",
}


def source_key(source: Any) -> str:
    """把来源标识归一化为内部配对键；未知来源原样返回。"""
    if source is None:
        return ""
    text = str(source).strip()
    return SOURCE_ALIASES.get(text.lower(), SOURCE_ALIASES.get(text, text))


def pair_key(source_a: Any, source_b: Any) -> tuple[str, str]:
    """返回与参数顺序无关的来源对键。"""
    a, b = source_key(source_a), source_key(source_b)
    return tuple(sorted((a, b)))  # type: ignore[return-value]


def _now() -> datetime:
    return datetime.now()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 异常体系
# ---------------------------------------------------------------------------

class SourceSharingError(Exception):
    """多源共享去重领域错误基类。"""


class UnauthorizedSharingError(SourceSharingError, PermissionError):
    """没有有效双方授权却尝试跨来源读取/归并——越权。"""


class UnauthorizedMergeError(UnauthorizedSharingError):
    """未获许可的跨来源归并。"""


class FingerprintAccessDenied(UnauthorizedSharingError):
    """共享权限不足，无法读取对方来源的指纹或日志。"""


class AuthorizationConflictError(SourceSharingError):
    """存在多份互相冲突的授权，且没有选定双方凭证。"""


class CredentialError(SourceSharingError):
    """双方凭证不匹配、失效或签名错误。"""


class ScopeRevokedError(SourceSharingError):
    """共享范围已被某一方撤销，不能再按该范围发起新归并/重发。"""


class InvestigationStateError(SourceSharingError):
    """调查当前状态不允许该操作。"""


class DeliveryInterruptedError(SourceSharingError):
    """采样侧已交付，但未收到授权侧确认；交付处于待核清（in-doubt）状态。"""

    def __init__(self, message: str, receipt: "DeliveryReceipt | None" = None):
        super().__init__(message)
        self.receipt = receipt


class AmbiguousTransportError(SourceSharingError):
    """传输结果不明确（对端可能已收到，例如确认超时）。"""


class ContentDisputeError(SourceSharingError):
    """共享键相同但内容矛盾，且调用方要求争议直接抛错。"""

    def __init__(self, message: str, dispute: "Dispute | None" = None):
        super().__init__(message)
        self.dispute = dispute


class RecoveryConflictError(SourceSharingError):
    """恢复时发现原交付与当前/manifest 不一致，拒绝猜测性重发。"""


# ---------------------------------------------------------------------------
# 灵活字段访问：核心结果同时支持属性与字典风格访问
# ---------------------------------------------------------------------------

class Flex:
    """让 dataclass / 普通对象同时支持 ``obj.x``、``obj["x"]``、``obj.get``。"""

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            value = getattr(self, key)
            if isinstance(value, (list, dict, str, int, float, bool)) or value is None:
                return value
            return value
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, AttributeError):
            return default

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError


def _dataclass_to_dict(obj: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in getattr(obj, "__dataclass_fields__", {}):
        value = getattr(obj, f)
        if isinstance(value, Flex):
            out[f] = value.to_dict()
        elif isinstance(value, (list, tuple)):
            out[f] = [_dataclass_to_dict(v) if hasattr(v, "__dataclass_fields__")
                      else v for v in value]
        elif isinstance(value, datetime):
            out[f] = value.isoformat()
        else:
            out[f] = value
    return out


# ---------------------------------------------------------------------------
# 原行与证据位置
# ---------------------------------------------------------------------------

@dataclass
class LineRef(Flex):
    """一条原行的可核对引用：来源 + 行号/位置 + 校验值 + 原文摘录。"""

    source: str
    line_number: int | None = None
    line_id: str = ""
    location: str = ""
    checksum: str = ""
    raw_line: str = ""
    request_code: str = ""
    content: dict[str, Any] = field(default_factory=dict)

    # -- 兼容性别名 -------------------------------------------------------
    @property
    def source_id(self) -> str:
        return self.source

    @property
    def line_no(self) -> int | None:
        return self.line_number

    @property
    def raw(self) -> str:
        return self.raw_line

    @property
    def uid(self) -> str:
        return self.line_id

    def __post_init__(self) -> None:
        if not self.location:
            if self.line_number is not None:
                self.location = f"{self.source}:L{self.line_number}"
            else:
                self.location = f"{self.source}:{self.checksum[:12]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "line_number": self.line_number,
            "line_id": self.line_id,
            "location": self.location,
            "checksum": self.checksum,
            "raw_line": self.raw_line,
            "request_code": self.request_code,
            "content": dict(self.content),
        }


@dataclass
class OriginalLine(Flex):
    """来自某个来源的一条真实日志原行。

    位置参数顺序为自然的 ``(source, line_number, raw_line)``，其余关键字传入。
    """

    source: str
    line_number: int | None = None
    raw_line: str = ""
    request_code: str = ""
    content: dict[str, Any] = field(default_factory=dict)
    path: str = ""
    record_id: str = ""
    event_time: datetime | None = None
    line_id: str = ""
    checksum: str = ""
    received_seq: int = 0

    def __post_init__(self) -> None:
        if not self.checksum:
            self.checksum = _sha256(self.raw_line or json.dumps(
                self.content, ensure_ascii=False, sort_keys=True, default=str))
        if not self.line_id:
            if self.line_number is not None:
                self.line_id = f"{source_key(self.source)}#L{self.line_number}"
            else:
                self.line_id = f"{source_key(self.source)}#sha:{self.checksum[:16]}"

    # -- 常用别名 ---------------------------------------------------------
    @property
    def source_id(self) -> str:
        return self.source

    @property
    def uid(self) -> str:
        return self.line_id

    @property
    def raw(self) -> str:
        return self.raw_line

    @property
    def line_no(self) -> int | None:
        return self.line_number

    @property
    def location(self) -> str:
        if self.path and self.line_number is not None:
            return f"{self.path}:{self.line_number}"
        if self.line_number is not None:
            return f"{self.source}:L{self.line_number}"
        return f"{self.source}:{self.checksum[:12]}"

    def content_digest(self, ignore_fields: Iterable[str] | None = None) -> str:
        ignore = set(ignore_fields or ())
        if self.content:
            payload = {k: v for k, v in self.content.items() if k not in ignore}
            text = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        else:
            text = self.raw_line
        return _sha256(text)

    def fingerprint(self, scope_id: str | None = None) -> str:
        """来源内指纹；给出共享范围时派生跨来源可比的共享指纹。"""
        if scope_id:
            return _sha256(f"shared|{scope_id}|{self.request_code}")
        return _sha256(f"local|{source_key(self.source)}|{self.request_code}"
                       f"|{self.content_digest()}")

    def ref(self) -> LineRef:
        return LineRef(
            source=self.source,
            line_number=self.line_number,
            line_id=self.line_id,
            location=self.location,
            checksum=self.checksum,
            raw_line=self.raw_line,
            request_code=self.request_code,
            content=dict(self.content),
        )

    def to_dict(self) -> dict[str, Any]:
        return _dataclass_to_dict(self)


# ---------------------------------------------------------------------------
# 双方凭证、共享范围与授权中心
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceCredential(Flex):
    """某一来源签发给某次共享的凭证（代表该方批准）。

    两份来源相对、scope_id 相同的凭证构成“选定的双方凭证”。
    """

    source: str
    partner: str
    scope_id: str = "default"
    credential_id: str = ""
    token: str = ""
    issued_at: datetime = field(default_factory=_now)
    expires_at: datetime | None = None
    version: int = 1

    def __post_init__(self) -> None:
        if not self.credential_id:
            cid = _sha256(f"cred|{self.source}|{self.partner}|{self.scope_id}"
                          f"|{self.issued_at.isoformat()}|{uuid.uuid4().hex[:8]}")[:16]
            object.__setattr__(self, "credential_id", cid)
        if not self.token:
            token = _sha256(f"token|{self.credential_id}|{self.source}"
                            f"|{self.partner}|{self.scope_id}|{self.version}")
            object.__setattr__(self, "token", token)

    @property
    def source_key(self) -> str:
        return source_key(self.source)

    @property
    def partner_key(self) -> str:
        return source_key(self.partner)

    def matches(self, other: "SourceCredential") -> bool:
        return (
            self.source_key == other.partner_key
            and self.partner_key == other.source_key
            and self.scope_id == other.scope_id
        )

    def expired(self, at: datetime | None = None) -> bool:
        return self.expires_at is not None and (at or _now()) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "source": self.source,
            "partner": self.partner,
            "scope_id": self.scope_id,
            "version": self.version,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


# 语义化别名
BilateralCredential = SourceCredential
SharingCredential = SourceCredential
Credential = SourceCredential


class SharingScope(Flex):
    """来源共享去重范围：明确同组的两个来源 + 共享键。

    普通构造出的范围 :attr:`authorized` 为 False，直接拿去归并属于越权；
    只有经授权中心双方批准（或调用方明确给出已批准凭证/范围）后才生效。
    """

    def __init__(
        self,
        *args: Any,
        sources: Any = None,  # 兼容 SharingScope(sources=("A","B"))
        pair: Iterable[Any] | None = None,
        scope_id: str = "SCOPE-AB",
        request_key: str = "request_code",
        merge_key: str | None = None,
        agreement_id: str | None = None,
        authorized: bool | None = None,
        approved: bool | None = None,
        name: str = "",
    ) -> None:
        collected: list[Any] = list(args)
        if sources is not None:
            collected.extend(sources)
        if pair is not None:
            collected.extend(pair)
        # 支持 SharingScope(["A","B"]) 这种单个可迭代位置参数
        if len(collected) == 1 and isinstance(collected[0], (list, tuple, set, frozenset)):
            collected = list(collected[0])
        if len(collected) != 2:
            raise ValueError("来源共享去重范围必须且只能明确包含两个来源")
        self.sources: tuple[str, str] = (str(collected[0]), str(collected[1]))
        self.scope_id = scope_id
        self.request_key = merge_key or request_key
        self.agreement_id = agreement_id
        flag = authorized if authorized is not None else approved
        self.authorized: bool = bool(flag)
        self.name = name
        self.created_at = _now()

    @property
    def approved(self) -> bool:
        return self.authorized

    @approved.setter
    def approved(self, value: bool) -> None:
        self.authorized = value

    @property
    def pair(self) -> tuple[str, str]:
        return self.sources

    @property
    def pair_key(self) -> tuple[str, str]:
        return pair_key(*self.sources)

    def covers(self, source_a: Any, source_b: Any = None) -> bool:
        if source_b is None:
            key = source_key(source_a)
            return key in self.pair_key
        return pair_key(source_a, source_b) == self.pair_key

    def contains(self, source: Any) -> bool:
        return source_key(source) in self.pair_key

    def __repr__(self) -> str:
        return (f"SharingScope({self.sources}, scope_id={self.scope_id!r}, "
                f"authorized={self.authorized})")

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "sources": list(self.sources),
            "pair_key": list(self.pair_key),
            "request_key": self.request_key,
            "agreement_id": self.agreement_id,
            "authorized": self.authorized,
            "name": self.name,
        }


@dataclass
class SharingAgreement(Flex):
    """一份经双方凭证成立的共享协议。"""

    agreement_id: str
    scope: SharingScope
    credentials: tuple[SourceCredential, SourceCredential]
    status: str = "active"  # active | revoked
    approved_at: datetime = field(default_factory=_now)
    revoked_by: str = ""
    revoked_at: datetime | None = None
    revoke_reason: str = ""
    version: int = 1

    @property
    def pair_key(self) -> tuple[str, str]:
        return self.scope.pair_key

    @property
    def sources(self) -> tuple[str, str]:
        return self.scope.sources

    def involves(self, source: Any) -> bool:
        return self.scope.contains(source)

    def revoke(self, by: str = "", reason: str = "") -> None:
        if self.status != "active":
            return
        self.status = "revoked"
        self.revoked_by = by
        self.revoke_reason = reason
        self.revoked_at = _now()
        self.scope.authorized = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "agreement_id": self.agreement_id,
            "status": self.status,
            "scope": self.scope.to_dict(),
            "credentials": [c.to_dict() for c in self.credentials],
            "approved_at": self.approved_at.isoformat(),
            "revoked_by": self.revoked_by,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoke_reason": self.revoke_reason,
            "version": self.version,
        }


# 语义化别名
BilateralConsent = SharingAgreement
SharingGrant = SharingAgreement


class AuthorizationCenter(Flex):
    """双方授权/凭证/共享权限的登记与裁决中心。

    别名 :class:`SharingRegistry` / :class:`ConsentRegistry`。
    """

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or _now
        self.credentials: dict[str, SourceCredential] = {}
        self.agreements: dict[str, SharingAgreement] = {}
        #: pair_key -> agreement_id 列表（可能存在多版本/冲突授权）
        self._by_pair: dict[tuple[str, str], list[str]] = {}
        self.audit_log: list[dict[str, Any]] = []
        self._seq = 0

    # -- 审计 -------------------------------------------------------------
    def audit(self, action: str, **detail: Any) -> dict[str, Any]:
        entry = {"at": self._clock().isoformat(), "action": action, **detail}
        self.audit_log.append(entry)
        return entry

    # -- 凭证 -------------------------------------------------------------
    def issue_credential(
        self,
        source: Any,
        partner: Any = None,
        *,
        scope_id: str = "default",
        ttl_minutes: int | None = None,
        expires_at: datetime | None = None,
        version: int = 1,
    ) -> SourceCredential:
        if partner is None:
            raise CredentialError("签发凭证必须指明对方来源 partner")
        exp = expires_at
        if exp is None and ttl_minutes is not None:
            exp = self._clock() + timedelta(minutes=ttl_minutes)
        cred = SourceCredential(
            source=str(source), partner=str(partner), scope_id=scope_id,
            expires_at=exp, version=version,
            issued_at=self._clock(),
        )
        self.credentials[cred.credential_id] = cred
        self.audit("credential_issued", source=str(source), partner=str(partner),
                   scope_id=scope_id, credential_id=cred.credential_id)
        return cred

    def _select_credentials(
        self,
        credentials: Iterable[SourceCredential] | None,
        credential_ids: Iterable[str] | None = None,
    ) -> tuple[SourceCredential, SourceCredential]:
        creds = list(credentials or [])
        for cid in credential_ids or []:
            if cid not in self.credentials:
                raise CredentialError(f"凭证不存在或未登记：{cid}")
            creds.append(self.credentials[cid])
        if len(creds) != 2:
            raise CredentialError("成立双方共享必须且只能选定两份来源凭证")
        a, b = creds[0], creds[1]
        if not a.matches(b):
            raise AuthorizationConflictError(
                f"双方凭证不构成同一共享范围：{a.source}/{a.partner}/{a.scope_id} "
                f"vs {b.source}/{b.partner}/{b.scope_id}")
        at = self._clock()
        for c in (a, b):
            if c.expired(at):
                raise CredentialError(f"凭证已过期：{c.credential_id}")
        return a, b

    # -- 批准 / 授权 ------------------------------------------------------
    def approve_pair(
        self,
        source_a: Any = None,
        source_b: Any = None,
        *,
        credentials: Iterable[SourceCredential] | None = None,
        credential_ids: Iterable[str] | None = None,
        scope_id: str | None = None,
        agreement_id: str | None = None,
    ) -> SharingAgreement:
        """凭选定的两份双方凭证成立共享；也可用 source_a/source_b 走快捷双方批准。"""
        if credentials is not None or credential_ids is not None:
            ca, cb = self._select_credentials(credentials, credential_ids)
            sid = scope_id or ca.scope_id
        else:
            if source_a is None or source_b is None:
                raise CredentialError("批准共享必须提供两个来源或两份双方凭证")
            sid = scope_id or "default"
            ca = self.issue_credential(source_a, source_b, scope_id=sid)
            cb = self.issue_credential(source_b, source_a, scope_id=sid)
            ca, cb = self._select_credentials([ca, cb], None)
        pk = pair_key(ca.source, cb.source)
        aid = agreement_id or f"AGREE-{pk[0]}-{pk[1]}-{len(self.agreements) + 1:03d}"
        scope = SharingScope(
            ca.source, cb.source, scope_id=sid, agreement_id=aid,
            authorized=True, name=f"{pk[0]}↔{pk[1]} 共享去重范围")
        agreement = SharingAgreement(
            agreement_id=aid, scope=scope, credentials=(ca, cb),
            approved_at=self._clock())
        self.agreements[aid] = agreement
        self._by_pair.setdefault(pk, []).append(aid)
        self.audit("sharing_approved", agreement_id=aid, pair=list(pk), scope_id=sid,
                   credential_ids=[ca.credential_id, cb.credential_id])
        return agreement

    #: 语义化快捷别名：登记一次双方批准（测试/演示常用）
    def grant(self, *args: Any, **kwargs: Any) -> SharingAgreement:
        return self.approve_pair(*args, **kwargs)

    def grant_sharing(self, *args: Any, **kwargs: Any) -> SharingAgreement:
        return self.approve_pair(*args, **kwargs)

    def authorize(self, *args: Any, **kwargs: Any) -> SharingAgreement:
        return self.approve_pair(*args, **kwargs)

    # 更多语义化方法别名
    approve_sharing = approve_pair
    create_agreement = approve_pair
    grant_consent = approve_pair
    add_bilateral_authorization = approve_pair

    # -- 查询 / 冲突裁决 --------------------------------------------------
    def active_agreements(self, source_a: Any = None, source_b: Any = None) -> list[SharingAgreement]:
        if source_a is None:
            return [a for a in self.agreements.values() if a.status == "active"]
        pk = pair_key(source_a, source_b)
        return [self.agreements[aid] for aid in self._by_pair.get(pk, [])
                if self.agreements[aid].status == "active"]

    def active_agreement(
        self,
        source_a: Any,
        source_b: Any,
        *,
        credentials: Iterable[SourceCredential] | None = None,
        credential_ids: Iterable[str] | None = None,
        agreement_id: str | None = None,
        scope_id: str | None = None,
    ) -> SharingAgreement | None:
        """按“选定的双方凭证”裁决当前应适用的协议。

        - 指定 agreement_id / 凭证：精确选定，并校验有效性；
        - 该来源对仅有一份生效协议：直接返回；
        - 存在多份冲突授权且未选定：抛 :class:`AuthorizationConflictError`。
        """
        actives = self.active_agreements(source_a, source_b)
        if agreement_id is not None:
            ag = self.agreements.get(agreement_id)
            if ag is None or ag.status != "active":
                raise ScopeRevokedError(f"协议不存在或已撤销：{agreement_id}")
            return ag
        if credentials is not None or credential_ids is not None:
            ca, cb = self._select_credentials(credentials, credential_ids)
            cred_pair = pair_key(ca.source, cb.source)
            if source_a is not None and source_b is not None and \
                    pair_key(source_a, source_b) != cred_pair:
                raise UnauthorizedMergeError(
                    f"选定凭证属于来源对 {list(cred_pair)}，"
                    f"不能授权来源对 {list(pair_key(source_a, source_b))} 的读取/归并")
            wanted = {ca.scope_id}
            matches = [a for a in actives if a.scope.scope_id in wanted]
            if matches:
                return matches[-1]
            # 选定的两份凭证相互匹配（互为对方、同一 scope、未过期）本身即构成
            # 双方批准：据此补登记协议，保证后续审计/撤销有同一凭据锚点。
            return self.approve_pair(credentials=[ca, cb])
        if scope_id is not None:
            matches = [a for a in actives if a.scope.scope_id == scope_id]
            if not matches:
                return None
            if len(matches) > 1:
                raise AuthorizationConflictError(f"scope {scope_id} 存在多份冲突协议，请选定双方凭证")
            return matches[0]
        if not actives:
            return None
        if len(actives) == 1:
            return actives[0]
        raise AuthorizationConflictError(
            f"来源对 {pair_key(source_a, source_b)} 存在 {len(actives)} 份生效且可能冲突的授权，"
            f"请按选定的双方凭证/agreement_id 处理")

    def active_scope(self, source_a: Any, source_b: Any, **kwargs: Any) -> SharingScope | None:
        ag = self.active_agreement(source_a, source_b, **kwargs)
        return ag.scope if ag else None

    # -- 撤销 -------------------------------------------------------------
    def revoke(
        self,
        source: Any = None,
        partner: Any = None,
        *,
        agreement_id: str | None = None,
        scope_id: str | None = None,
        by: str = "",
        reason: str = "任一方撤销共享",
    ) -> list[SharingAgreement]:
        """任一方撤销：可按协议 id，或撤销某来源（与 partner 之间）的共享。"""
        revoked: list[SharingAgreement] = []
        if agreement_id is not None:
            ag = self.agreements.get(agreement_id)
            if ag is None:
                raise KeyError(f"协议不存在：{agreement_id}")
            ag.revoke(by=by or str(source or ""), reason=reason)
            revoked.append(ag)
        else:
            for ag in self.active_agreements(source, partner):
                if scope_id is not None and ag.scope.scope_id != scope_id:
                    continue
                if partner is None or ag.involves(partner):
                    ag.revoke(by=by or str(source), reason=reason)
                    revoked.append(ag)
        for ag in revoked:
            self.audit("sharing_revoked", agreement_id=ag.agreement_id,
                       pair=list(ag.pair_key), revoked_by=ag.revoked_by, reason=reason)
        return revoked

    def revoke_sharing(self, *args: Any, **kwargs: Any) -> list[SharingAgreement]:
        return self.revoke(*args, **kwargs)

    # -- 共享读取权限：指纹 / 日志 ---------------------------------------
    def can_read(
        self,
        reader: Any,
        owner: Any,
        *,
        credentials: Iterable[SourceCredential] | None = None,
        agreement_id: str | None = None,
    ) -> bool:
        r, o = source_key(reader), source_key(owner)
        if not r or r == o:
            return True
        try:
            return self.active_agreement(
                reader, owner, credentials=credentials,
                agreement_id=agreement_id) is not None
        except SourceSharingError:
            return False

    def require_read(self, reader: Any, owner: Any, **kwargs: Any) -> SharingAgreement:
        r, o = source_key(reader), source_key(owner)
        if r == o:
            # 来源读自己：构造/返回 None 由调用方按 source_local 处理
            return None  # type: ignore[return-value]
        ag = self.active_agreement(reader, owner, **kwargs)
        if ag is None:
            self.audit("access_denied", reader=r, owner=o, kind="fingerprint/log")
            raise FingerprintAccessDenied(
                f"来源 {reader} 未经 {owner} 与自己双方批准共享，"
                f"无权读取对方指纹或日志；此次归并属于越权")
        return ag

    def fingerprint_for(
        self,
        reader: Any,
        line: OriginalLine,
        *,
        credentials: Iterable[SourceCredential] | None = None,
        agreement_id: str | None = None,
    ) -> str:
        """按共享权限返回可读指纹：自己的原行给本地指纹，获授权后给共享指纹。"""
        if source_key(reader) == source_key(line.source):
            return line.fingerprint()
        ag = self.require_read(reader, line.source, credentials=credentials,
                               agreement_id=agreement_id)
        return line.fingerprint(ag.scope.scope_id)

    def read_lines(
        self,
        reader: Any,
        lines: Iterable[OriginalLine],
        **kwargs: Any,
    ) -> list[OriginalLine]:
        """共享权限决定可读取的日志：逐行校验来源读权限。"""
        result: list[OriginalLine] = []
        for line in lines:
            self.require_read(reader, line.source, **kwargs)
            result.append(line)
        return result


# 语义化别名
SharingRegistry = AuthorizationCenter
ConsentRegistry = AuthorizationCenter
SharingAuthorization = AuthorizationCenter


# ---------------------------------------------------------------------------
# 输入归一化：兼容 OriginalLine / dict / EventRecord / LogEntry
# ---------------------------------------------------------------------------

_SOURCE_KEYS = ("source", "source_id", "log_source", "from_source", "src",
                "source_host", "host")
_LINE_NO_KEYS = ("line_number", "line_no", "lineno", "line")
_RAW_KEYS = ("raw_line", "raw", "original_content", "message", "content_text")
_CODE_KEYS = ("request_code", "code", "req_code", "request_id", "共享键")
_CONTENT_KEYS = ("content", "parsed_fields", "fields", "payload")


def _first(mapping: Any, keys: Iterable[str]) -> Any:
    if isinstance(mapping, dict):
        for k in keys:
            if k in mapping and mapping[k] not in (None, ""):
                return mapping[k]
        return None
    for k in keys:
        if hasattr(mapping, k):
            v = getattr(mapping, k)
            if v not in (None, ""):
                return v
    return None


def coerce_line(item: Any, *, code_field: str | None = None,
                seq: int = 0) -> OriginalLine:
    """把多种输入形态归一化为 :class:`OriginalLine`。"""
    if isinstance(item, OriginalLine):
        if not item.received_seq:
            item.received_seq = seq
        return item

    if isinstance(item, LineRef):
        return OriginalLine(
            source=item.source, raw_line=item.raw_line,
            line_number=item.line_number, request_code=item.request_code,
            line_id=item.line_id, checksum=item.checksum, received_seq=seq)

    # EventRecord / LogEntry / dict 等
    source = _first(item, _SOURCE_KEYS) or ""
    line_number = _first(item, _LINE_NO_KEYS)
    raw_line = _first(item, _RAW_KEYS) or ""
    if not isinstance(raw_line, str):
        raw_line = str(raw_line)

    content = _first(item, _CONTENT_KEYS)
    if content is None:
        content = {}
    if not isinstance(content, dict):
        content = {"value": content}
    else:
        content = dict(content)

    code = None
    if code_field:
        code = content.get(code_field) or _first(item, [code_field])
    if not code:
        code = _first(item, _CODE_KEYS) or content.get(code_field or "request_code")
    code = str(code or "")

    # EventRecord 场景：request_code 可能只在 parsed_fields 里
    if not code and isinstance(getattr(item, "parsed_fields", None), dict):
        pf = item.parsed_fields
        code = str(pf.get(code_field or "request_code")
                   or next((pf[k] for k in ("code", "req_code", "request_id") if k in pf), ""))

    path = _first(item, ("path", "log_path", "file_path")) or ""
    record_id = _first(item, ("record_id", "id")) or ""
    event_time = _first(item, ("event_time", "timestamp", "time"))
    checksum = _first(item, ("checksum",)) or ""
    line_id = _first(item, ("line_id", "uid")) or ""
    if not line_id and record_id:
        line_id = f"{source_key(source)}#rec:{record_id}"

    try:
        line_number = int(line_number) if line_number not in (None, "") else None
    except (TypeError, ValueError):
        line_number = None

    return OriginalLine(
        source=str(source), raw_line=raw_line, line_number=line_number,
        request_code=code, content=content, path=str(path or ""),
        record_id=str(record_id or ""), event_time=event_time
        if isinstance(event_time, datetime) else None,
        checksum=str(checksum or ""), line_id=str(line_id or ""),
        received_seq=seq,
    )


# ---------------------------------------------------------------------------
# 归组结果与争议
# ---------------------------------------------------------------------------

@dataclass
class Dispute(Flex):
    """共享键相同但内容矛盾的争议：全部来源证据原样保留、隔离。"""

    dispute_id: str
    request_code: str
    scope_id: str | None
    pair: tuple[str, str]
    refs: list[LineRef] = field(default_factory=list)
    lines: list[OriginalLine] = field(default_factory=list)
    digests: dict[str, str] = field(default_factory=dict)
    reason: str = "同一共享键对应互相矛盾的请求内容"
    created_at: datetime = field(default_factory=_now)

    @property
    def evidence(self) -> list[LineRef]:
        return self.refs

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispute_id": self.dispute_id,
            "request_code": self.request_code,
            "scope_id": self.scope_id,
            "pair": list(self.pair),
            "refs": [r.to_dict() for r in self.refs],
            "digests": self.digests,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class DedupGroup(Flex):
    """一个去重组：来源内独立组，或授权范围内的跨来源折叠组。"""

    group_key: str
    request_code: str
    mode: str  # source_local | shared
    sources: list[str]
    source_keys: list[str]
    lines: list[OriginalLine] = field(default_factory=list)
    representative: OriginalLine | None = None
    refs: list[LineRef] = field(default_factory=list)
    scope: SharingScope | None = None
    status: str = "unique"  # unique | collapsed | duplicate | disputed
    dispute: Dispute | None = None
    collapsed_count: int = 0

    @property
    def evidence_refs(self) -> list[LineRef]:
        return self.refs

    @property
    def origin_refs(self) -> list[LineRef]:
        return self.refs

    @property
    def is_disputed(self) -> bool:
        return self.status == "disputed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_key": self.group_key,
            "request_code": self.request_code,
            "mode": self.mode,
            "sources": self.sources,
            "source_keys": self.source_keys,
            "status": self.status,
            "representative": self.representative.ref().to_dict() if self.representative else None,
            "refs": [r.to_dict() for r in self.refs],
            "scope": self.scope.to_dict() if self.scope else None,
            "dispute": self.dispute.to_dict() if self.dispute else None,
            "collapsed_count": self.collapsed_count,
        }


class DedupResult(list):
    """去重结果：本身是 :class:`DedupGroup` 列表，另带统计/争议/审计。"""

    def __init__(self, groups: Iterable[DedupGroup], *,
                 total_lines: int = 0, retransmissions: int = 0,
                 removed: int = 0, scopes: list[SharingScope] | None = None,
                 disputes: list[Dispute] | None = None,
                 audit: list[dict[str, Any]] | None = None) -> None:
        super().__init__(groups)
        self.total_lines = total_lines
        self.retransmissions = retransmissions
        self.hit_count = removed
        self.removed = removed
        self.ignore_count = removed
        self.scopes = scopes or []
        self.disputes = disputes or []
        self.audit = audit or []

    @property
    def groups(self) -> list[DedupGroup]:
        return list(self)

    @property
    def deduped(self) -> list[DedupGroup]:
        return list(self)

    def stats(self) -> dict[str, int]:
        return {
            "total_lines": self.total_lines,
            "groups": len(self),
            "retransmissions": self.retransmissions,
            "hit_count": self.hit_count,
            "disputes": len(self.disputes),
            "shared_groups": sum(1 for g in self if g.mode == "shared"),
        }

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


# ---------------------------------------------------------------------------
# 权限依据（每个样本/领取都能交代当时权限）
# ---------------------------------------------------------------------------

@dataclass
class PermissionBasis(Flex):
    """记录一次归并/领取发生时所依据的权限快照。"""

    mode: str = "source_local"  # source_local | bilateral_shared
    decided_at: datetime = field(default_factory=_now)
    scope_id: str | None = None
    agreement_id: str | None = None
    pair: list[str] = field(default_factory=list)
    credential_ids: list[str] = field(default_factory=list)
    status_at_decision: str = "no_cross_source_grant"
    detail: str = "无跨来源双方授权，按来源各自独立去重/采样"

    def to_dict(self) -> dict[str, Any]:
        return _dataclass_to_dict(self)

    def describe(self) -> str:
        if self.mode == "bilateral_shared":
            return (f"依据双方授权协议 {self.agreement_id}（范围 {self.scope_id}，"
                    f"来源对 {'/'.join(self.pair)}，凭证 {','.join(self.credential_ids)}）"
                    f"于 {self.decided_at.isoformat(timespec='seconds')} 跨来源折叠")
        return f"按来源独立处理（{self.status_at_decision}）：{self.detail}"


# ---------------------------------------------------------------------------
# 核心入口一：deduplicate 归组
# ---------------------------------------------------------------------------

def _line_order_key(line: OriginalLine) -> tuple[Any, ...]:
    return (
        line.event_time or datetime.min,
        line.line_number if line.line_number is not None else -1,
        line.received_seq,
    )


def select_representative(
    lines: list[OriginalLine], policy: str = "latest"
) -> OriginalLine | None:
    """按保留策略选唯一代表。

    - ``first``/``earliest``：最早到达/最前行号（去重入口的首见语义）；
    - ``latest``（采样归并与 SampleConfig 的既有默认）：最新事件时间。
    """
    if not lines:
        return None
    if policy in ("first", "earliest", "first_seen"):
        return min(lines, key=_line_order_key)
    return max(lines, key=_line_order_key)


def _build_authorized_scopes(
    *,
    scope: SharingScope | None,
    scopes: Iterable[SharingScope] | None,
    center: AuthorizationCenter | None,
    credentials: Iterable[SourceCredential] | None,
    agreement_id: str | None,
) -> tuple[dict[tuple[str, str], SharingScope], list[dict[str, Any]]]:
    """把显式范围 / 授权中心 / 选定凭证统一裁决为 pair -> 生效范围。"""
    audit: list[dict[str, Any]] = []
    effective: dict[tuple[str, str], SharingScope] = {}

    explicit: list[SharingScope] = []
    if scope is not None:
        explicit.append(scope)
    if scopes:
        explicit.extend(list(scopes))

    for sc in explicit:
        if not isinstance(sc, SharingScope):
            raise TypeError("sharing scope 必须是 SharingScope")
        # 显式范围必须带有已批准标记，或能在中心核实为 active
        if not sc.authorized:
            if center is not None:
                ag = center.active_agreement(*sc.sources, agreement_id=sc.agreement_id)
                if ag is not None:
                    sc = ag.scope
            if not sc.authorized:
                raise UnauthorizedMergeError(
                    f"来源 {sc.sources} 的共享去重范围未经双方批准/凭证授权，"
                    f"按该范围折叠相同请求码属于越权：{sc.scope_id}")
        elif center is not None:
            # 即使自带 authorized 标记，若中心显示已撤销也不得使用
            ag = center.agreements.get(sc.agreement_id) if sc.agreement_id else \
                center.active_agreement(*sc.sources)
            if ag is not None and ag.status != "active":
                raise ScopeRevokedError(f"共享范围已撤销：{ag.agreement_id}")
        effective[sc.pair_key] = sc
        audit.append({"action": "apply_scope", "scope_id": sc.scope_id,
                      "pair": list(sc.pair_key), "authorized": True})

    if credentials is not None:
        creds = list(credentials)
        if center is None:
            # 调用方直接给出“选定的双方凭证”：校验自洽后据此成立临时范围
            if len(creds) != 2 or not creds[0].matches(creds[1]):
                raise AuthorizationConflictError("选定的两份凭证不构成匹配的双方凭证")
            ca, cb = creds
            sc = SharingScope(ca.source, cb.source, scope_id=ca.scope_id,
                              authorized=True)
            effective[sc.pair_key] = sc
            audit.append({"action": "apply_selected_credentials",
                          "credential_ids": [ca.credential_id, cb.credential_id]})
        else:
            ag = center.active_agreement(
                creds[0].source, creds[0].partner, credentials=creds,
                agreement_id=agreement_id)
            effective[ag.pair_key] = ag.scope

    if center is not None:
        for ag in center.active_agreements():
            effective.setdefault(ag.pair_key, ag.scope)

    return effective, audit


def deduplicate(
    lines: Iterable[Any] | None = None,
    dedup_rule: Any = None,
    *,
    records: Iterable[Any] | None = None,
    items: Iterable[Any] | None = None,
    request_code_field: str = "request_code",
    code_field: str | None = None,
    scope: SharingScope | None = None,
    sharing_scope: SharingScope | None = None,
    scopes: Iterable[SharingScope] | None = None,
    sharing_scopes: Iterable[SharingScope] | None = None,
    center: AuthorizationCenter | None = None,
    authorization: AuthorizationCenter | None = None,
    registry: AuthorizationCenter | None = None,
    auth: AuthorizationCenter | None = None,
    credentials: Iterable[SourceCredential] | None = None,
    creds: Iterable[SourceCredential] | None = None,
    agreement_id: str | None = None,
    retain_policy: str = "first",
    ignore_content_fields: Iterable[str] | None = None,
    enforce_reads: bool = False,
    reader: Any = None,
    raise_on_dispute: bool = False,
    **_unused: Any,
) -> DedupResult:
    """按“来源共享去重范围”对相同请求码归组。

    - 默认（无授权范围）：同一请求码在每个来源各成一组（A/B/C 各一条）；
      同一原行重传幂等，不多占格。
    - 双方批准的 pair 范围：pair 内相同请求码折叠为一个 :class:`DedupGroup`，
      保留全部原行引用作为证据；无关来源不参与。
    - 内容矛盾：组状态为 disputed，进入 ``result.disputes`` 隔离。
    - 传入未授权的 scope：抛 :class:`UnauthorizedMergeError`（越权）。
    """
    raw_items: list[Any] = list(lines if lines is not None else
                                records if records is not None else
                                items if items is not None else [])
    center = center or authorization or registry or auth
    credentials = credentials or creds
    scope = scope or sharing_scope
    scopes = scopes or sharing_scopes
    code_field = code_field or request_code_field

    # 1) 归一化 + 原行幂等（重传同一原行不多占格）
    normalized: list[OriginalLine] = []
    seen_uids: set[str] = set()
    retransmissions = 0
    for seq, item in enumerate(raw_items):
        line = coerce_line(item, code_field=code_field, seq=seq)
        if not line.request_code:
            # 没有请求码的行不参与请求码归并，独立成组（用 uid 作为键）
            line.request_code = f"__no_code__:{line.line_id}"
        if line.line_id in seen_uids:
            retransmissions += 1
            continue
        seen_uids.add(line.line_id)
        normalized.append(line)

    # 2) 裁决授权范围（未授权显式范围直接抛越权）
    center_audit_start = len(center.audit_log) if center is not None else 0
    effective_scopes, scope_audit = _build_authorized_scopes(
        scope=scope, scopes=scopes, center=center,
        credentials=credentials, agreement_id=agreement_id)

    # 3) 可选：以某读取方身份逐行校验指纹/日志读取权限
    if enforce_reads and reader is not None and center is not None:
        for line in normalized:
            center.require_read(reader, line.source, credentials=credentials,
                                agreement_id=agreement_id)

    # 4) 按请求码分桶
    buckets: dict[str, list[OriginalLine]] = {}
    for line in normalized:
        buckets.setdefault(line.request_code, []).append(line)

    groups: list[DedupGroup] = []
    disputes: list[Dispute] = []
    removed = retransmissions
    dispute_seq = 0

    for code, bucket in buckets.items():
        # 4.1 来源内分组
        by_source: dict[str, list[OriginalLine]] = {}
        for line in bucket:
            by_source.setdefault(source_key(line.source), []).append(line)

        # 4.2 用授权 pair 边做并查集（只可能把明确同组的两个来源连起来）
        keys = list(by_source.keys())
        parent = {k: k for k in keys}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        applied_scope_for_root: dict[str, SharingScope] = {}
        for pk, sc in effective_scopes.items():
            if pk[0] in by_source and pk[1] in by_source:
                union(pk[0], pk[1])
                applied_scope_for_root[find(pk[0])] = sc

        clusters: dict[str, list[OriginalLine]] = {}
        cluster_scope: dict[str, SharingScope | None] = {}
        for k in keys:
            root = find(k)
            clusters.setdefault(root, [])
            clusters[root].extend(by_source[k])
            if root in applied_scope_for_root:
                cluster_scope[root] = applied_scope_for_root[root]
            else:
                # 合并后的 root 可能不是当时记录的 root，按键再找一次 scope
                for pk, sc in effective_scopes.items():
                    if pk[0] in by_source and pk[1] in by_source and find(pk[0]) == root:
                        cluster_scope[root] = sc
                        break
                else:
                    cluster_scope.setdefault(root, None)

        # 4.3 每个簇形成一个 DedupGroup
        for root, member_lines in clusters.items():
            member_lines.sort(key=lambda ln: (
                ln.line_number is None,
                ln.line_number if ln.line_number is not None else ln.received_seq,
                ln.received_seq,
            ))
            sc = cluster_scope.get(root)
            src_keys = sorted({source_key(ln.source) for ln in member_lines})
            src_values: list[str] = []
            for ln in member_lines:
                if ln.source not in src_values:
                    src_values.append(ln.source)
            shared = sc is not None and len(src_keys) >= 2

            # 代表选择：去重入口默认首见保留；可显式切到 latest
            rep = select_representative(member_lines, retain_policy)
            if rep is None:
                rep = member_lines[0]

            refs: list[LineRef] = []
            seen_ref: set[str] = set()
            for ln in member_lines:
                r = ln.ref()
                if r.line_id not in seen_ref:
                    refs.append(r)
                    seen_ref.add(r.line_id)

            intra_removed = len(member_lines) - len(src_keys)
            cross_removed = (len(src_keys) - 1) if shared else 0
            removed += max(0, intra_removed) + max(0, cross_removed)

            base_key = code.split(":", 2)[-1] if code.startswith("__no_code__:") else code
            gkey = f"{'SH' if shared else 'SRC'}:{sc.scope_id if sc else src_keys[0]}:{base_key}"

            group = DedupGroup(
                group_key=gkey,
                request_code=base_key,
                mode="shared" if shared else "source_local",
                sources=src_values,
                source_keys=src_keys,
                lines=member_lines,
                representative=rep,
                refs=refs,
                scope=sc if shared else None,
                collapsed_count=len(member_lines),
            )

            # 4.4 仅对跨来源共享组做内容矛盾检测
            if shared:
                digests = {source_key(ln.source): ln.content_digest(ignore_content_fields)
                           for ln in member_lines}
                if len(set(digests.values())) > 1:
                    dispute_seq += 1
                    dispute = Dispute(
                        dispute_id=f"DISP-{dispute_seq:03d}-{base_key}",
                        request_code=base_key,
                        scope_id=sc.scope_id if sc else None,
                        pair=tuple(src_keys[:2]),  # type: ignore[arg-type]
                        refs=refs,
                        lines=list(member_lines),
                        digests=digests,
                    )
                    group.status = "disputed"
                    group.representative = None
                    group.dispute = dispute
                    disputes.append(dispute)
                    if raise_on_dispute:
                        raise ContentDisputeError(dispute.reason, dispute=dispute)
                else:
                    group.status = "collapsed"
            else:
                group.status = "duplicate" if len(member_lines) > 1 else "unique"

            groups.append(group)

    groups.sort(key=lambda g: g.group_key)
    stats_audit = list(scope_audit)
    if center is not None:
        stats_audit.extend(center.audit_log[center_audit_start:])
    return DedupResult(
        groups, total_lines=len(raw_items), retransmissions=retransmissions,
        removed=removed, scopes=list(effective_scopes.values()),
        disputes=disputes, audit=stats_audit)


# 语义化别名
group_by_source_sharing = deduplicate
dedup_sources = deduplicate


# ---------------------------------------------------------------------------
# 样本与 sample 入口
# ---------------------------------------------------------------------------

@dataclass
class Sample(Flex):
    """一次实际领取的样本：唯一代表 + 全部原行证据位置 + 当时权限依据。"""

    sample_id: str
    group_key: str
    request_code: str
    kind: str = "representative"  # representative | dispute
    representative: LineRef | None = None
    origin_refs: list[LineRef] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    source_keys: list[str] = field(default_factory=list)
    basis: PermissionBasis = field(default_factory=PermissionBasis)
    dispute: Dispute | None = None
    claim_id: str = ""
    created_at: datetime = field(default_factory=_now)

    @property
    def origins(self) -> list[LineRef]:
        return self.origin_refs

    @property
    def origin_lines(self) -> list[LineRef]:
        """样本所依据的各来源原行（含位置/校验值/原文/字段）。"""
        return self.origin_refs

    @property
    def original_lines(self) -> list[LineRef]:
        return self.origin_refs

    @property
    def evidence(self) -> list[LineRef]:
        return self.origin_refs

    @property
    def is_dispute(self) -> bool:
        return self.kind == "dispute"

    def origin_locations(self) -> list[str]:
        return [r.location for r in self.origin_refs]

    def origin_uids(self) -> list[str]:
        return [r.line_id for r in self.origin_refs]

    def provenance(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.origin_refs]

    def to_dict(self) -> dict[str, Any]:
        d = _dataclass_to_dict(self)
        d["origin_locations"] = self.origin_locations()
        return d


class SampleSet(list):
    """同一次调查/采样的样本集合；本身可迭代、可取长度，也带清单与溯源表。"""

    def __init__(self, samples: Iterable[Sample], *,
                 investigation_id: str = "",
                 basis_summary: str = "",
                 created_at: datetime | None = None) -> None:
        super().__init__(samples)
        self.investigation_id = investigation_id
        self.basis_summary = basis_summary
        self.created_at = created_at or _now()
        self.manifest_id = f"MANIFEST-{investigation_id or 'STANDALONE'}-{uuid.uuid4().hex[:8]}"

    @property
    def samples(self) -> list[Sample]:
        return list(self)

    @property
    def all_samples(self) -> list[Sample]:
        return list(self)

    @property
    def disputes(self) -> list[Dispute]:
        return [s.dispute for s in self if s.dispute is not None]

    def origin_table(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for s in self:
            rows.append({
                "sample_id": s.sample_id,
                "request_code": s.request_code,
                "kind": s.kind,
                "sources": list(s.sources),
                "representative": s.representative.location if s.representative else None,
                "origins": [
                    {"source": r.source, "line_number": r.line_number,
                     "location": r.location, "checksum": r.checksum[:12]}
                    for r in s.origin_refs
                ],
                "basis": s.basis.mode,
            })
        return rows

    def manifest(self) -> dict[str, Any]:
        """冻结的交付清单：只含原行身份/位置与权限依据，供幂等恢复核对。"""
        return {
            "manifest_id": self.manifest_id,
            "investigation_id": self.investigation_id,
            "created_at": self.created_at.isoformat(),
            "basis_summary": self.basis_summary,
            "samples": [
                {
                    "sample_id": s.sample_id,
                    "kind": s.kind,
                    "request_code": s.request_code,
                    "representative_uid": s.representative.line_id if s.representative else None,
                    "origin_uids": [r.line_id for r in s.origin_refs],
                    "origin_locations": [r.location for r in s.origin_refs],
                    "basis": s.basis.to_dict(),
                }
                for s in self
            ],
        }

    def manifest_fingerprint(self) -> str:
        return _sha256(json.dumps(self.manifest(), ensure_ascii=False,
                                  sort_keys=True, default=str))

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


def _basis_from_group(group: DedupGroup) -> PermissionBasis:
    if group.mode == "shared" and group.scope is not None:
        return PermissionBasis(
            mode="bilateral_shared",
            scope_id=group.scope.scope_id,
            agreement_id=group.scope.agreement_id,
            pair=list(group.scope.pair_key),
            status_at_decision="active_bilateral_agreement",
            detail=f"按已批准的来源共享去重范围 {group.scope.scope_id} 折叠")
    return PermissionBasis()


def sample(
    groups_or_lines: Any = None,
    config: Any = None,
    *,
    groups: Iterable[DedupGroup] | None = None,
    records: Iterable[Any] | None = None,
    lines: Iterable[Any] | None = None,
    result: DedupResult | None = None,
    center: AuthorizationCenter | None = None,
    authorization: AuthorizationCenter | None = None,
    credentials: Iterable[SourceCredential] | None = None,
    scope: SharingScope | None = None,
    sharing_scope: SharingScope | None = None,
    ratio: float | None = None,
    sample_ratio: float | None = None,
    retain_policy: str | None = None,
    investigation_id: str = "",
    raise_on_dispute: bool = False,
    **kwargs: Any,
) -> SampleSet:
    """按归组结果实际领取每组唯一代表。

    - 普通组：一个代表样本 + 全部原行证据引用；
    - 争议组：生成 kind="dispute" 的隔离样本，保留各来源全部证据，
      representative 为 None（不任选一条原行）；
    - 也可以直接传原行，函数会先用相同授权参数执行 :func:`deduplicate`。
    """
    center = center or authorization
    scope = scope or sharing_scope
    if ratio is None:
        ratio = sample_ratio
    if ratio is None and config is not None:
        ratio = getattr(config, "sample_ratio", None)
    ratio = 1.0 if ratio is None else float(ratio)

    merge_key = kwargs.pop("merge_key", None) or getattr(config, "merge_key", "") or None
    code_field = kwargs.pop("code_field", None) or merge_key or "request_code"
    # 采样归并的保留策略沿用 SampleConfig 默认（latest），可被显式参数覆盖
    policy = retain_policy or getattr(config, "retain_policy", None) or "latest"

    # 取得归组结果
    if result is not None:
        dedup_result = result
    elif groups is not None:
        dedup_result = groups if isinstance(groups, DedupResult) else DedupResult(groups)
    elif isinstance(groups_or_lines, DedupResult):
        dedup_result = groups_or_lines
    elif isinstance(groups_or_lines, list) and groups_or_lines and \
            isinstance(groups_or_lines[0], DedupGroup):
        dedup_result = DedupResult(groups_or_lines)
    else:
        raw = groups_or_lines if groups_or_lines is not None else \
            lines if lines is not None else records
        if raw is None:
            raw = []
        dedup_result = deduplicate(
            raw, center=center, credentials=credentials, scope=scope,
            code_field=code_field,
            retain_policy=retain_policy or "first",
            raise_on_dispute=raise_on_dispute, **kwargs)

    group_list = list(dedup_result)

    # 采样比例（与既有管道一致：max(1, int(n*ratio)) 的前缀选取）
    if 0 < ratio < 1.0 and group_list:
        threshold = max(1, int(len(group_list) * ratio))
        group_list = group_list[:threshold]

    samples: list[Sample] = []
    seq = 0
    for g in group_list:
        seq += 1
        sid = f"SAMP-{investigation_id + '-' if investigation_id else ''}{seq:03d}"
        basis = _basis_from_group(g)
        if g.status == "disputed":
            samples.append(Sample(
                sample_id=sid, group_key=g.group_key, request_code=g.request_code,
                kind="dispute", representative=None,
                origin_refs=list(g.refs), sources=list(g.sources),
                source_keys=list(g.source_keys), basis=basis, dispute=g.dispute))
        else:
            # 采样入口按自己的保留策略（默认 latest）从全组原行实际选代表
            chosen = select_representative(g.lines, policy) or g.representative
            rep_ref = chosen.ref() if chosen is not None else None
            samples.append(Sample(
                sample_id=sid, group_key=g.group_key, request_code=g.request_code,
                kind="representative", representative=rep_ref,
                origin_refs=list(g.refs), sources=list(g.sources),
                source_keys=list(g.source_keys), basis=basis))

    summary = "；".join(sorted({s.basis.mode for s in samples})) or "empty"
    return SampleSet(samples, investigation_id=investigation_id, basis_summary=summary)


# 语义化别名
merge_and_sample = sample


# ---------------------------------------------------------------------------
# 领取（Claim）、调查（Investigation）、确认并发控制
# ---------------------------------------------------------------------------

@dataclass
class Claim(Flex):
    """一次“实际领取”的组代表候选，带领取时刻的权限快照。"""

    claim_id: str
    group_key: str
    request_code: str
    representative: LineRef | None
    origin_refs: list[LineRef]
    sources: list[str]
    source_keys: list[str]
    basis: PermissionBasis
    status: str = "held"  # held | superseded | confirmed
    dispute: Dispute | None = None
    claimed_at: datetime = field(default_factory=_now)
    superseded_by: str = ""

    def to_sample(self, sample_id: str) -> Sample:
        return Sample(
            sample_id=sample_id, group_key=self.group_key,
            request_code=self.request_code,
            kind="dispute" if self.dispute is not None else "representative",
            representative=None if self.dispute else self.representative,
            origin_refs=list(self.origin_refs), sources=list(self.sources),
            source_keys=list(self.source_keys), basis=self.basis,
            dispute=self.dispute, claim_id=self.claim_id)

    def to_dict(self) -> dict[str, Any]:
        return _dataclass_to_dict(self)


@dataclass
class AuditEntry(Flex):
    at: str
    action: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _dataclass_to_dict(self)


class Investigation:
    """一次调查：领取候选 → 待确认 → 并发安全确认 → 交付/恢复。"""

    def __init__(self, investigation_id: str, office: "SamplingOffice",
                 lines: Iterable[Any] | None = None) -> None:
        self.investigation_id = investigation_id
        self.office = office
        self.lines: list[OriginalLine] = [
            ln if isinstance(ln, OriginalLine) else coerce_line(ln, seq=i)
            for i, ln in enumerate(lines or [])
        ]
        self.claims: list[Claim] = []
        self.superseded_claims: list[Claim] = []
        self.sample_set: SampleSet | None = None
        self.receipt: "DeliveryReceipt | None" = None
        self.receipts: dict[str, "DeliveryReceipt"] = {}
        self.audit: list[AuditEntry] = []
        self.status: str = "open"  # open|pending|confirmed|interrupted|delivered|acknowledged
        self.lock = threading.RLock()
        self.created_at = _now()

    def _log(self, action: str, **detail: Any) -> None:
        entry = AuditEntry(at=_now().isoformat(), action=action, detail=detail)
        self.audit.append(entry)
        self.office.audit_log.append({
            "investigation_id": self.investigation_id, **entry.to_dict()})

    @property
    def samples(self) -> list["Sample"]:
        """确认后的样本列表；未确认时为空。"""
        return list(self.sample_set) if self.sample_set is not None else []

    @property
    def result(self) -> "SampleSet | None":
        return self.sample_set

    # -- 输入 -------------------------------------------------------------
    def add_lines(self, lines: Iterable[Any]) -> None:
        with self.lock:
            for i, item in enumerate(lines):
                self.lines.append(item if isinstance(item, OriginalLine)
                                  else coerce_line(item, seq=len(self.lines) + i))
            self._log("lines_added", count=len(list(lines)))

    # -- 权限冲突核对 -----------------------------------------------------
    def permission_conflicts(self) -> list[dict[str, Any]]:
        """指出“领取时权限”与“当前授权范围”的冲突（例如领取后 A/B 才获批）。"""
        conflicts: list[dict[str, Any]] = []
        center = self.office.center
        line_sources = {source_key(ln.source) for ln in self.lines}
        for claim in self.claims:
            if claim.status != "held":
                continue
            if claim.basis.mode != "source_local":
                continue
            sk = set(claim.source_keys)
            for src in list(sk):
                for other in line_sources - sk:
                    ag = center.active_agreement(src, other) if center else None
                    if ag is not None and any(
                            l.request_code == claim.request_code
                            and source_key(l.source) == source_key(other)
                            for l in self.lines):
                        conflicts.append({
                            "claim_id": claim.claim_id,
                            "request_code": claim.request_code,
                            "claim_basis": claim.basis.mode,
                            "now_available_agreement": ag.agreement_id,
                            "pair": [src, source_key(other)],
                            "options": ["keep_claims", "reclaim_shared"],
                        })
        return conflicts

    # -- 领取 -------------------------------------------------------------
    def claim(
        self,
        lines: Iterable[Any] | None = None,
        *,
        credentials: Iterable[SourceCredential] | None = None,
        scope: SharingScope | None = None,
        strategy: str | None = None,
    ) -> list[Claim]:
        with self.lock:
            if self.sample_set is not None:
                raise InvestigationStateError("调查已确认并固化样本，不能再次领取；请新建调查")
            if lines is not None:
                self.add_lines(lines)
            result = deduplicate(
                self.lines, center=self.office.center,
                credentials=credentials, scope=scope or self.office.default_scope,
                retain_policy=self.office.retain_policy)
            held: list[Claim] = []
            for i, g in enumerate(result):
                basis = _basis_from_group(g)
                cid = f"CLAIM-{self.investigation_id}-{len(self.claims) + len(held) + 1:03d}"
                claim = Claim(
                    claim_id=cid, group_key=g.group_key, request_code=g.request_code,
                    representative=g.representative.ref() if g.representative else None,
                    origin_refs=list(g.refs), sources=list(g.sources),
                    source_keys=list(g.source_keys), basis=basis,
                    dispute=g.dispute, status="held")
                held.append(claim)
            self.claims = [c for c in self.claims if c.status == "superseded"] + held
            self.status = "pending"
            self._log("claimed", claim_ids=[c.claim_id for c in held],
                      modes=[c.basis.mode for c in held])
            return held

    def reclaim(
        self,
        *,
        credentials: Iterable[SourceCredential] | None = None,
        scope: SharingScope | None = None,
    ) -> list[Claim]:
        """授权变化后重领：旧领取标记 superseded 但保留审计，按新权限实际领取。"""
        with self.lock:
            if self.sample_set is not None:
                raise InvestigationStateError("调查已确认，不能重领；权限变化只对新调查生效")
            for c in self.claims:
                if c.status == "held":
                    c.status = "superseded"
                    c.superseded_by = "reclaim_under_new_authorization"
                    self.superseded_claims.append(c)
            self._log("reclaim", superseded=[c.claim_id for c in self.claims
                                             if c.status == "superseded"])
            return self.claim(credentials=credentials, scope=scope)

    # -- 确认（并发幂等） -------------------------------------------------
    def confirm(
        self,
        *,
        conflict: str = "keep_claims",
        strategy: str | None = None,
        credentials: Iterable[SourceCredential] | None = None,
        scope: SharingScope | None = None,
    ) -> SampleSet:
        """确认本次调查，并发调用只保留同一份样本集合。

        conflict/strategy:
        - ``keep_claims``（默认）：沿用已领取候选，样本保留领取时的权限依据，
          同样足以交代当时权限（先各采一条）。
        - ``reclaim_shared``：先按新批准的双方凭证重领，再合成跨来源代表。
        """
        mode = strategy or conflict
        with self.lock:
            if self.sample_set is not None:
                # 并发/重试确认：只返回已固化的同一份样本
                self._log("confirm_idempotent_reuse",
                          manifest=self.sample_set.manifest_id)
                return self.sample_set

            if mode in ("reclaim", "reclaim_shared", "shared"):
                self.reclaim(credentials=credentials, scope=scope)
            elif not self.claims or all(c.status == "superseded" for c in self.claims):
                self.claim(credentials=credentials, scope=scope)

            active_claims = [c for c in self.claims if c.status == "held"]
            samples = [c.to_sample(f"SAMP-{self.investigation_id}-{i + 1:03d}")
                       for i, c in enumerate(active_claims)]
            basis_modes = sorted({s.basis.mode for s in samples})
            summary = "mixed:" + "+".join(basis_modes) if len(basis_modes) > 1 else (
                basis_modes[0] if basis_modes else "empty")
            ss = SampleSet(samples, investigation_id=self.investigation_id,
                           basis_summary=summary)
            for c in active_claims:
                c.status = "confirmed"
            self.sample_set = ss
            self.status = "confirmed"
            self._log("confirmed", manifest_id=ss.manifest_id,
                      sample_count=len(ss),
                      sample_uids=[[r.line_id for r in s.origin_refs] for s in ss])
            return ss


# ---------------------------------------------------------------------------
# 交付传输与回执
# ---------------------------------------------------------------------------

@dataclass
class DeliveryReceipt(Flex):
    idempotency_key: str
    investigation_id: str
    manifest: dict[str, Any]
    manifest_fingerprint: str
    status: str = "sent_unconfirmed"  # sent_unconfirmed|interrupted|acknowledged|resent
    attempts: int = 0
    ack_id: str = ""
    created_at: datetime = field(default_factory=_now)
    recovered_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _dataclass_to_dict(self)


class RecordingTransport:
    """内存传输/授权侧收件箱，可模拟“对端收到但确认丢失”。"""

    def __init__(self, *, lose_ack: bool = False, fail_send_times: int = 0) -> None:
        self.inbox: dict[str, dict[str, Any]] = {}
        self.acks: dict[str, str] = {}
        self.send_attempts = 0
        self.lose_ack = lose_ack
        self.fail_send_times = fail_send_times

    def send(self, envelope: dict[str, Any]) -> str:
        self.send_attempts += 1
        key = envelope["idempotency_key"]
        if self.fail_send_times > 0:
            self.fail_send_times -= 1
            raise AmbiguousTransportError("发送失败/超时，无法判断授权侧是否收到")
        # 授权侧实际收到并按幂等键去重
        self.inbox[key] = envelope
        if self.lose_ack:
            raise AmbiguousTransportError("授权侧已收件，但确认(ack)返回丢失")
        ack_id = f"ACK-{key}"
        self.acks[key] = ack_id
        return ack_id


# ---------------------------------------------------------------------------
# 采样办公室：串联 claim/confirm/deliver/recover
# ---------------------------------------------------------------------------

class SamplingOffice(Flex):
    """调查与交付的统一入口（别名 InvestigationService / SharedDedupSampler）。"""

    def __init__(self, center: AuthorizationCenter | None = None, *,
                 transport: RecordingTransport | None = None,
                 retain_policy: str = "latest",
                 default_scope: SharingScope | None = None) -> None:
        self.center = center or AuthorizationCenter()
        self.transport = transport or RecordingTransport()
        self.retain_policy = retain_policy
        self.default_scope = default_scope
        self.investigations: dict[str, Investigation] = {}
        self._idem: dict[str, DeliveryReceipt] = {}
        self.audit_log: list[dict[str, Any]] = []
        self._id_seq = 0
        self._global_lock = threading.Lock()

    # -- 调查管理 ---------------------------------------------------------
    def open_investigation(
        self,
        investigation_id: str | None = None,
        *,
        id: str | None = None,  # noqa: A002 - 兼容 id= 关键字
        name: str = "",
        lines: Iterable[Any] | None = None,
    ) -> Investigation:
        iid = investigation_id or id
        if iid is None:
            with self._global_lock:
                self._id_seq += 1
                iid = f"INV-{self._id_seq:03d}"
        if iid in self.investigations:
            return self.investigations[iid]
        inv = Investigation(iid, self, lines=lines)
        self.investigations[iid] = inv
        inv._log("opened", name=name)
        return inv

    create_investigation = open_investigation

    def get(self, investigation_id: str) -> Investigation:
        if investigation_id not in self.investigations:
            raise KeyError(f"调查不存在：{investigation_id}")
        return self.investigations[investigation_id]

    # -- 薄门面：直接以 office 为入口领取/确认 ---------------------------
    def claim(self, investigation: Any, lines: Iterable[Any] | None = None,
              **kwargs: Any) -> list[Claim]:
        return self._inv(investigation).claim(lines, **kwargs)

    claim_candidates = claim

    def confirm(self, investigation: Any, **kwargs: Any) -> SampleSet:
        return self._inv(investigation).confirm(**kwargs)

    # 便捷串联：deduplicate -> claim -> confirm
    def deduplicate(self, lines: Iterable[Any] | None = None, **kwargs: Any) -> DedupResult:
        """入口一：在本办公室授权中心裁决下归组。"""
        kwargs.setdefault("center", self.center)
        return deduplicate(lines, **kwargs)  # type: ignore[misc]

    def sample(self, lines_or_groups: Any = None, **kwargs: Any) -> SampleSet:
        """入口二：在本办公室授权中心裁决下实际领取各组唯一代表。"""
        kwargs.setdefault("center", self.center)
        return sample(lines_or_groups, **kwargs)  # type: ignore[misc]

    def run(
        self,
        investigation_id: str | None = None,
        lines: Iterable[Any] | None = None,
        *,
        conflict: str = "keep_claims",
        credentials: Iterable[SourceCredential] | None = None,
        scope: SharingScope | None = None,
    ) -> SampleSet:
        inv = self.open_investigation(investigation_id, lines=lines)
        if not inv.claims:
            inv.claim(credentials=credentials, scope=scope)
        return inv.confirm(conflict=conflict, credentials=credentials, scope=scope)

    # -- 交付（两阶段，幂等） ---------------------------------------------
    def deliver(
        self,
        investigation: Investigation | str,
        *,
        idempotency_key: str | None = None,
        regroup: bool = False,
    ) -> DeliveryReceipt:
        inv = self._inv(investigation)
        with inv.lock:
            if inv.sample_set is None:
                raise InvestigationStateError("调查尚未确认，没有可交付的样本")

            # 撤销后禁止按“新分组”重新合成/重发
            if regroup:
                revoked = [a for a in self.center.agreements.values()
                           if a.status == "revoked"]
                if revoked:
                    raise ScopeRevokedError(
                        "共享已被撤销：不能按撤销后的新分组重发同一原行；"
                        "只能恢复并核对原交付")

            key = idempotency_key or f"DELIV-{inv.investigation_id}"
            # 幂等：同键重试直接返回原回执，绝不二次发送
            if key in self._idem:
                old = self._idem[key]
                inv.receipt = old
                inv._log("deliver_idempotent_reuse", key=key, status=old.status)
                return old

            ss = inv.sample_set
            manifest = ss.manifest()
            fp = ss.manifest_fingerprint()
            receipt = DeliveryReceipt(
                idempotency_key=key, investigation_id=inv.investigation_id,
                manifest=manifest, manifest_fingerprint=fp,
                status="sent_unconfirmed")
            inv.receipts[key] = receipt
            self._idem[key] = receipt

            envelope = {"idempotency_key": key, "manifest": manifest,
                        "manifest_fingerprint": fp}
            receipt.attempts += 1
            try:
                ack_id = self.transport.send(envelope)
            except AmbiguousTransportError as exc:
                # 采样侧可能已交付，但授权侧确认未收到 -> 中断待核清
                receipt.status = "interrupted"
                inv.receipt = receipt
                inv.status = "interrupted"
                inv._log("delivery_interrupted", key=key, error=str(exc))
                raise DeliveryInterruptedError(
                    f"调查 {inv.investigation_id} 交付后未收到授权侧确认，"
                    f"已中断；恢复前必须先核清原交付：{exc}", receipt=receipt) from exc

            receipt.ack_id = ack_id
            receipt.status = "acknowledged"
            inv.receipt = receipt
            inv.status = "acknowledged"
            inv._log("delivered_acknowledged", key=key, ack=ack_id)
            return receipt

    def acknowledge(self, key_or_receipt: str | DeliveryReceipt,
                    ack_id: str = "") -> DeliveryReceipt:
        """授权侧补送确认（例如核清原交付后）。"""
        receipt = key_or_receipt if isinstance(key_or_receipt, DeliveryReceipt) \
            else self._idem[key_or_receipt]
        receipt.status = "acknowledged"
        receipt.ack_id = ack_id or f"ACK-{receipt.idempotency_key}"
        inv = self.get(receipt.investigation_id)
        inv.receipt = receipt
        if inv.status == "interrupted":
            inv.status = "acknowledged"
        inv._log("acknowledged", key=receipt.idempotency_key, ack=receipt.ack_id)
        return receipt

    # -- 恢复：先核清原交付，再决定确认或按原 manifest 补发 ---------------
    def verify_original_delivery(
        self, investigation: Investigation | str,
        *, idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        inv = self._inv(investigation)
        key = idempotency_key or (inv.receipt.idempotency_key if inv.receipt
                                  else f"DELIV-{inv.investigation_id}")
        receipt = self._idem.get(key) or (inv.receipt if inv.receipt and
                                          inv.receipt.idempotency_key == key else None)
        remote = self.transport.inbox.get(key)
        local_fp = receipt.manifest_fingerprint if receipt else (
            inv.sample_set.manifest_fingerprint() if inv.sample_set else None)
        remote_fp = remote.get("manifest_fingerprint") if remote else None
        same = bool(local_fp and remote_fp and local_fp == remote_fp)
        report = {
            "idempotency_key": key,
            "has_local_receipt": receipt is not None,
            "authorization_side_received": remote is not None,
            "manifest_identical": same,
            "local_fingerprint": local_fp,
            "remote_fingerprint": remote_fp,
            "original_origin_uids": (
                [o for s in receipt.manifest["samples"] for o in s["origin_uids"]]
                if receipt else []),
        }
        return report

    def recover(
        self,
        investigation_or_key: Investigation | str,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """恢复中断的交付。

        步骤严格为：
        1. 找到原回执与冻结 manifest；
        2. 与授权侧收件箱核对“原交付”（同幂等键 + 同 manifest 指纹）；
        3. 若授权侧已收到原件：补确认，不重发；
        4. 若授权侧未收到：按 *原 manifest* 补发（同一批原行、同一幂等键），
           绝不按撤销后的新分组重新归并。
        """
        if isinstance(investigation_or_key, str) and \
                investigation_or_key in self._idem and idempotency_key is None and \
                investigation_or_key not in self.investigations:
            key = investigation_or_key
            receipt = self._idem[key]
            inv = self.get(receipt.investigation_id)
        else:
            inv = self._inv(investigation_or_key)
            key = idempotency_key or (inv.receipt.idempotency_key if inv.receipt
                                      else f"DELIV-{inv.investigation_id}")
            receipt = self._idem.get(key)

        if receipt is None:
            raise InvestigationStateError(f"找不到需要恢复的原交付回执：{key}")

        with inv.lock:
            check = self.verify_original_delivery(inv, idempotency_key=key)
            if check["authorization_side_received"]:
                if not check["manifest_identical"]:
                    raise RecoveryConflictError(
                        "授权侧留存的交付 manifest 与本地原交付不一致；"
                        "拒绝按任何新分组重发同一原行，需人工核清")
                self.acknowledge(receipt)
                receipt.recovered_action = "confirmed_original_delivery"
                inv.status = "acknowledged"
                inv._log("recovered_confirmed_original", key=key)
                return {"action": "confirmed_original", "resent": False,
                        "receipt": receipt.to_dict(), "check": check}

            # 授权侧没收到 -> 用冻结的原 manifest 补发，不重新分组
            envelope = {"idempotency_key": key, "manifest": receipt.manifest,
                        "manifest_fingerprint": receipt.manifest_fingerprint}
            receipt.attempts += 1
            ack_id = self.transport.send(envelope)
            receipt.ack_id = ack_id
            receipt.status = "acknowledged"
            receipt.recovered_action = "resent_original_manifest"
            inv.status = "acknowledged"
            inv.receipt = receipt
            inv._log("recovered_resent_original_manifest", key=key, ack=ack_id,
                     attempts=receipt.attempts)
            return {"action": "resent_original", "resent": True,
                    "receipt": receipt.to_dict(), "check": check}

    # -- 内部 -------------------------------------------------------------
    def _inv(self, investigation: Any) -> Investigation:
        if isinstance(investigation, Investigation):
            return investigation
        if isinstance(investigation, SampleSet) and investigation.investigation_id:
            return self.get(investigation.investigation_id)
        return self.get(investigation)


# 语义化别名
InvestigationService = SamplingOffice
SampleInvestigationService = SamplingOffice
SharedDedupSampler = SamplingOffice


# ---------------------------------------------------------------------------
# 甲、乙、丙真实输入样例
# ---------------------------------------------------------------------------

def build_jia_yi_bing_lines() -> list[OriginalLine]:
    """构造甲(A)/乙(B)/丙(C)三来源的真实风格日志原行。

    数据集：
    - ``REQ-7F3A-20261124-001``：三来源都有相同请求码且请求内容一致；
      甲的 L101 会被原样重传一次（同 line_id/checksum）。
    - ``REQ-9B2E-20261124-002``：甲/乙请求内容互相矛盾（200 vs 500、
      两个路径），丙同样持有但始终独立。
    """
    return [
        OriginalLine(
            source="甲", line_number=101,
            path="/var/log/gateway/jia-gateway.log",
            raw_line=("2026-11-24 09:00:01.218 [http-nio] INFO  c.g.Gateway - "
                      "request_code=REQ-7F3A-20261124-001 method=POST "
                      "path=/api/v1/settle status=200 amount=100.00"),
            request_code="REQ-7F3A-20261124-001",
            content={"method": "POST", "path": "/api/v1/settle",
                     "status": "200", "amount": "100.00"},
            event_time=datetime(2026, 11, 24, 9, 0, 1)),
        # 甲的同一原行被采集代理重传（行号与原文完全一致）
        OriginalLine(
            source="甲", line_number=101,
            path="/var/log/gateway/jia-gateway.log",
            raw_line=("2026-11-24 09:00:01.218 [http-nio] INFO  c.g.Gateway - "
                      "request_code=REQ-7F3A-20261124-001 method=POST "
                      "path=/api/v1/settle status=200 amount=100.00"),
            request_code="REQ-7F3A-20261124-001",
            content={"method": "POST", "path": "/api/v1/settle",
                     "status": "200", "amount": "100.00"},
            event_time=datetime(2026, 11, 24, 9, 0, 1)),
        OriginalLine(
            source="乙", line_number=205,
            path="/var/log/pay/yi-pay.log",
            raw_line=("2026-11-24 09:00:01.301 [worker-7] INFO  PayService - "
                      "request_code=REQ-7F3A-20261124-001 method=POST "
                      "path=/api/v1/settle status=200 amount=100.00"),
            request_code="REQ-7F3A-20261124-001",
            content={"method": "POST", "path": "/api/v1/settle",
                     "status": "200", "amount": "100.00"},
            event_time=datetime(2026, 11, 24, 9, 0, 1)),
        OriginalLine(
            source="丙", line_number=88,
            path="/var/log/audit/bing-audit.log",
            raw_line=("2026-11-24 09:00:01.410 [audit] INFO  AuditTrail - "
                      "request_code=REQ-7F3A-20261124-001 method=POST "
                      "path=/api/v1/settle status=200 amount=100.00"),
            request_code="REQ-7F3A-20261124-001",
            content={"method": "POST", "path": "/api/v1/settle",
                     "status": "200", "amount": "100.00"},
            event_time=datetime(2026, 11, 24, 9, 0, 1)),

        # --- 矛盾键 -----------------------------------------------------
        OriginalLine(
            source="甲", line_number=102,
            path="/var/log/gateway/jia-gateway.log",
            raw_line=("2026-11-24 09:05:11.002 [http-nio] INFO  c.g.Gateway - "
                      "request_code=REQ-9B2E-20261124-002 method=POST "
                      "path=/api/v1/refund status=200 amount=42.00"),
            request_code="REQ-9B2E-20261124-002",
            content={"method": "POST", "path": "/api/v1/refund",
                     "status": "200", "amount": "42.00"},
            event_time=datetime(2026, 11, 24, 9, 5, 11)),
        OriginalLine(
            source="乙", line_number=206,
            path="/var/log/pay/yi-pay.log",
            raw_line=("2026-11-24 09:05:11.544 [worker-7] ERROR PayService - "
                      "request_code=REQ-9B2E-20261124-002 method=POST "
                      "path=/api/v1/chargeback status=500 amount=999.00"),
            request_code="REQ-9B2E-20261124-002",
            content={"method": "POST", "path": "/api/v1/chargeback",
                     "status": "500", "amount": "999.00"},
            event_time=datetime(2026, 11, 24, 9, 5, 11)),
        OriginalLine(
            source="丙", line_number=89,
            path="/var/log/audit/bing-audit.log",
            raw_line=("2026-11-24 09:05:12.010 [audit] INFO  AuditTrail - "
                      "request_code=REQ-9B2E-20261124-002 observed "
                      "method=POST path=/api/v1/refund status=200"),
            request_code="REQ-9B2E-20261124-002",
            content={"method": "POST", "path": "/api/v1/refund",
                     "status": "200"},
            event_time=datetime(2026, 11, 24, 9, 5, 12)),
    ]


def filter_code(lines: Iterable[OriginalLine], code: str) -> list[OriginalLine]:
    """从真实数据集中取某个请求码的原行（保留甲的重传行用于幂等演示）。"""
    return [ln for ln in lines if ln.request_code == code]


# ---------------------------------------------------------------------------
# 语义化别名：兼容不同命名习惯下的导入
# ---------------------------------------------------------------------------

SourceLine = OriginalLine
SourceRecord = OriginalLine
LogLine = OriginalLine
Evidence = LineRef
EvidenceRef = LineRef
ProvenanceRef = LineRef

SourceSharingScope = SharingScope
SharedDedupScope = SharingScope
CrossSourceScope = SharingScope
DedupScope = SharingScope
PairSharingScope = SharingScope

BilateralSharing = SharingAgreement
SharingConsent = SharingAgreement
ConsentGrant = SharingAgreement
ConsentAgreement = SharingAgreement

ConsentCenter = AuthorizationCenter
GrantRegistry = AuthorizationCenter
BilateralAuthorization = AuthorizationCenter

SampleInvestigation = Investigation
InvestigationManager = SamplingOffice
InvestigationOffice = SamplingOffice
SourceSharingDedup = SamplingOffice
SharingDedupPipeline = SamplingOffice
SourceSharingPipeline = SamplingOffice
SourceSharingDedupPipeline = SamplingOffice
SharedDedupSamplingPipeline = SamplingOffice
SharedDedupService = SamplingOffice
DedupSamplingOffice = SamplingOffice

ClaimRecord = Claim
SampleRecord = Sample

# 方法级别名
Investigation.claim_candidates = Investigation.claim  # type: ignore[attr-defined]
Investigation.reclaim_shared = Investigation.reclaim  # type: ignore[attr-defined]


def make_source_sharing_pipeline(
    center: AuthorizationCenter | None = None, **kwargs: Any
) -> SamplingOffice:
    """工厂：创建多源共享去重/采样办公室（与 make_*_pipeline 命名习惯一致）。"""
    return SamplingOffice(center, **kwargs)


def make_sharing_office(
    center: AuthorizationCenter | None = None, **kwargs: Any
) -> SamplingOffice:
    return SamplingOffice(center, **kwargs)


def deduplicate_and_sample(
    lines: Iterable[Any] | None = None, **kwargs: Any
) -> SampleSet:
    """一步串联 deduplicate → sample（授权参数同 :func:`deduplicate`）。"""
    investigation_id = kwargs.pop("investigation_id", "")
    result = deduplicate(lines, **{k: v for k, v in kwargs.items()
                                   if k not in ("ratio", "sample_ratio")})
    ratio = kwargs.get("ratio", kwargs.get("sample_ratio"))
    return sample(result, ratio=ratio, investigation_id=investigation_id)

PermissionDeniedError = UnauthorizedSharingError
CrossSourceAuthorizationError = UnauthorizedMergeError
YuequanError = UnauthorizedMergeError
ConflictError = AuthorizationConflictError
