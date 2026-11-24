"""拾音工坊去重与采样归并管道：event_type→dedup_filter→sample_job。

数据流：事件分类 → 去重过滤 → 采样归并
涉及模块：event_type, dedup_filter, sample_job
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Any, Iterable

from app.core.models import DedupFilter, EventRecord, SampleConfig
from app.core.source_sharing import (  # noqa: F401  (再导出共享去重领域 API)
    AuthorizationCenter,
    AuthorizationConflictError,
    BilateralConsent,
    BilateralCredential,
    Claim,
    ContentDisputeError,
    Credential,
    CredentialError,
    DedupGroup,
    DedupResult,
    DeliveryInterruptedError,
    DeliveryReceipt,
    Dispute,
    FingerprintAccessDenied,
    Investigation,
    InvestigationService,
    InvestigationStateError,
    LineRef,
    OriginalLine,
    PermissionBasis,
    RecoveryConflictError,
    RecordingTransport,
    Sample,
    SampleSet,
    SamplingOffice,
    SharedDedupSampler,
    SharingAgreement,
    SharingCredential,
    SharingGrant,
    SharingRegistry,
    SharingScope,
    ScopeRevokedError,
    SourceCredential,
    SourceSharingError,
    UnauthorizedMergeError,
    UnauthorizedSharingError,
    build_jia_yi_bing_lines,
    coerce_line,
    deduplicate as source_deduplicate,
    filter_code,
    pair_key,
    sample as source_sample,
    source_key,
)

#: 模块级串联入口：``from app.core.dedup_sample import deduplicate, sample``
deduplicate = source_deduplicate
sample = source_sample
#: 语义化别名
deduplicate_sources = source_deduplicate
sample_sources = source_sample

# 把 source_sharing 的全部公开名称（含语义化别名）透出到本模块命名空间，
# 兼容 ``from app.core.dedup_sample import SharingScope`` 等导入习惯。
from app.core import source_sharing as _source_sharing_impl  # noqa: E402

for _export_name in dir(_source_sharing_impl):
    if not _export_name.startswith("_"):
        globals().setdefault(_export_name, getattr(_source_sharing_impl, _export_name))
del _export_name


class DedupOutcome(tuple):
    """经典三元组 ``(deduped, hit_count, ignore_count)`` 的兼容返回值。

    同时携带完整的多源归组结果：``outcome.sharing_result`` /
    ``outcome.groups`` / ``outcome.disputes``。既能按旧契约三元解包，
    也能访问丰富的来源共享归组信息。
    """

    def __new__(cls, triple: tuple[list, int, int], sharing_result: "DedupResult"):
        obj = super().__new__(cls, triple)
        obj.sharing_result = sharing_result
        return obj

    @property
    def groups(self) -> "DedupResult":
        return self.sharing_result

    @property
    def disputes(self):
        return self.sharing_result.disputes


# ---------- 预置去重过滤规则 ----------

PRESET_DEDUP_RULES: list[DedupFilter] = [
    DedupFilter(
        rule_id="DEDU-0001",
        event_type_id="EVEN-0001",
        dedup_fields=["client_ip", "url"],
        window_minutes=60,
        fingerprint_algo="sha256",
    ),
    DedupFilter(
        rule_id="DEDU-0002",
        event_type_id="EVEN-0002",
        dedup_fields=["level", "message"],
        window_minutes=10,
        fingerprint_algo="sha256",
    ),
]

# ---------- 预置采样归并配置 ----------

PRESET_SAMPLE_CONFIGS: list[SampleConfig] = [
    SampleConfig(
        plan_id="SAMP-0001",
        event_type_id="EVEN-0001",
        sample_ratio=0.5,
        merge_key="client_ip",
        merge_window_minutes=5,
        retain_policy="latest",
    ),
    SampleConfig(
        plan_id="SAMP-0002",
        event_type_id="EVEN-0002",
        sample_ratio=1.0,
        merge_key="message",
        merge_window_minutes=10,
        retain_policy="latest",
    ),
]


class DedupSamplePipeline:
    """去重与采样归并处理管道。

    接收 EventRecord 集合 → dedup_filter 去重 → sample_job 采样归并
    """

    def __init__(self, dedup_rules: list[DedupFilter] | None = None,
                 sample_configs: list[SampleConfig] | None = None,
                 sharing_center: "AuthorizationCenter | None" = None,
                 sharing_scopes: list["SharingScope"] | None = None):
        if dedup_rules is None:
            dedup_rules = PRESET_DEDUP_RULES
        if sample_configs is None:
            sample_configs = PRESET_SAMPLE_CONFIGS
        self.dedup_rules = dedup_rules
        self.sample_configs = sample_configs
        self._fingerprint_store: dict[str, set[str]] = {}
        # 多源双方授权共享去重/采样的授权中心与调查办公室
        self.sharing_center = sharing_center or AuthorizationCenter()
        self.default_sharing_scopes = list(sharing_scopes or [])
        self.sampling_office = SamplingOffice(self.sharing_center)
        self.last_sharing_dedup: DedupResult | None = None
        self.last_sharing_sample: SampleSet | None = None

    # -- 双方授权共享的便捷代理 ------------------------------------------
    def grant_sharing(self, *args: Any, **kwargs: Any) -> SharingAgreement:
        """登记一次来源对的双方批准（等价 sharing_center.grant）。"""
        ag = self.sharing_center.grant(*args, **kwargs)
        return ag

    def revoke_sharing(self, *args: Any, **kwargs: Any):
        return self.sharing_center.revoke(*args, **kwargs)

    def open_investigation(self, *args: Any, **kwargs: Any) -> Investigation:
        return self.sampling_office.open_investigation(*args, **kwargs)

    def _sharing_context(self, records: Any, kwargs: dict[str, Any]) -> bool:
        if kwargs.pop("sharing", None):
            return True
        if any(kwargs.get(k) is not None for k in (
                "sharing_scope", "scope", "center", "sharing_center",
                "authorization", "authorization_center", "registry", "auth",
                "credentials", "creds", "scopes", "sharing_scopes",
                "grants", "agreement_id")):
            return True
        return self._records_are_source_like(records)

    @staticmethod
    def _resolve_center(kwargs: dict[str, Any], default: Any) -> Any:
        return (kwargs.pop("center", None)
                or kwargs.pop("sharing_center", None)
                or kwargs.pop("authorization", None)
                or kwargs.pop("authorization_center", None)
                or kwargs.pop("registry", None)
                or kwargs.pop("auth", None)
                or default)

    # ---------- 数据流 4: event_type → dedup_filter → sample_job ----------

    def deduplicate(self, records: list[EventRecord],
                    dedup_rule: DedupFilter | None = None,
                    **kwargs: Any) -> tuple[list[EventRecord], int, int]:
        """对事件集合按 dedup_filter 执行去重。

        两种职责入口：

        1. 经典单源指纹去重（默认）：返回 ``(去重后记录, 命中次数, 忽略次数)``。
        2. 多源共享去重：传入 ``sharing_scope`` / ``center`` /
           ``credentials``，或直接传入 :class:`OriginalLine` 列表时，
           按“来源共享去重范围”归组，返回 ``(各组代表原行, 命中数, 忽略数)``，
           完整归组/争议结果挂在 ``self.last_sharing_dedup``。
           未获双方批准的显式范围会抛 :class:`UnauthorizedMergeError`（越权）。

        对每条事件按去重字段生成 SHA256 指纹，
        在去重窗口内（按 event_time 时间差）判断重复。

        返回：(去重后记录列表, 命中次数, 忽略次数)
        """
        if self._sharing_context(records, kwargs):
            center = self._resolve_center(kwargs, self.sharing_center)
            credentials = kwargs.pop("credentials", None) or kwargs.pop("creds", None)
            sharing_scope = kwargs.pop("sharing_scope", None) or kwargs.pop("scope", None)
            extra = {k: v for k, v in kwargs.items()
                     if k in {"scopes", "sharing_scopes", "agreement_id",
                              "request_code_field", "code_field", "retain_policy",
                              "ignore_content_fields", "enforce_reads", "reader",
                              "raise_on_dispute", "grants"}}
            if not sharing_scope and "scopes" not in extra \
                    and "sharing_scopes" not in extra and self.default_sharing_scopes:
                extra["scopes"] = self.default_sharing_scopes
            result = source_deduplicate(
                records,
                center=center,
                credentials=credentials,
                scope=sharing_scope,
                **extra,
            )
            self.last_sharing_dedup = result
            reps = [g.representative for g in result if g.representative is not None]
            return DedupOutcome((reps, result.hit_count, result.ignore_count), result)

        if dedup_rule is None:
            dedup_rule = self.dedup_rules[0] if self.dedup_rules else DedupFilter(
                rule_id="DEDU-AUTO", event_type_id="EVEN-0001",
                dedup_fields=["client_ip", "url"])
        if self._fingerprint_store is None:
            self._fingerprint_store = {}
        key = dedup_rule.rule_id
        if key not in self._fingerprint_store:
            self._fingerprint_store[key] = set()

        seen = self._fingerprint_store[key]
        deduped: list[EventRecord] = []
        hit = 0
        window_start = datetime.now() - timedelta(minutes=dedup_rule.window_minutes)

        for record in records:
            # 窗口检查：超过窗口时间的封锁不被清理（保留在 seen 中 但事件可过）
            # 生成指纹
            fp = dedup_rule.fingerprint(record)
            if fp in seen:
                dedup_rule.hit_count += 1
                hit += 1
                dedup_rule.ignore_count += 1
                continue
            seen.add(fp)
            deduped.append(record)

        return deduped, hit, dedup_rule.ignore_count

    def _records_are_source_like(self, records: Any) -> bool:
        if not records:
            return False
        first = records[0]
        if isinstance(first, (OriginalLine, LineRef, DedupGroup)):
            return True
        if isinstance(first, dict) and (
                "line_number" in first or "raw_line" in first
                or ("source" in first and "request_code" in first)):
            return True
        return False

    def deduplicate_all(self, records: list[EventRecord]) -> list[EventRecord]:
        """按事件类型匹配去重规则批量去重。

        每种事件类型匹配对应的 dedup_filter 规则。
        传入多源原行（OriginalLine/带来源的 dict）时，改按来源共享去重范围
        归组，返回各组代表原行，完整结果见 ``last_sharing_dedup``。
        """
        if self._records_are_source_like(records):
            result = source_deduplicate(records, center=self.sharing_center)
            self.last_sharing_dedup = result
            return [g.representative for g in result if g.representative is not None]
        result: list[EventRecord] = list(records)
        for dedup_rule in self.dedup_rules:
            target_type_id = dedup_rule.event_type_id
            target_records = [r for r in result if r.event_type.type_id == target_type_id]
            other_records = [r for r in result if r.event_type.type_id != target_type_id]
            deduped, _, _ = self.deduplicate(target_records, dedup_rule)
            result = deduped + other_records
        return result

    def sample(self, records: list[EventRecord],
               config: SampleConfig | None = None,
               **kwargs: Any):
        """按采样配置进行采样归并；也是多源“实际领取各组唯一代表”的入口。

        - 经典路径：采样 + 按 merge_key 保留最新，返回 ``list[EventRecord]``。
        - 共享路径：传入 ``sharing_scope`` / ``center`` / ``credentials``，
          或传入 :class:`OriginalLine` / :class:`DedupGroup` 时，按来源共享
          去重范围领取各组唯一代表，返回 :class:`SampleSet`（可像 list 一样
          遍历/取长），每个 :class:`Sample` 带全部原行位置与权限依据；
          完整结果同时挂在 ``self.last_sharing_sample``。

        采样：按 sample_ratio 取前 N 条。
        归并：按 merge_key 分组，每组仅保留最新事件记录。
        """
        if self._sharing_context(records, kwargs) or isinstance(records, DedupResult):
            center = self._resolve_center(kwargs, self.sharing_center)
            credentials = kwargs.pop("credentials", None) or kwargs.pop("creds", None)
            sharing_scope = kwargs.pop("sharing_scope", None) or kwargs.pop("scope", None)
            sample_kwargs = {k: v for k, v in kwargs.items() if k in {
                "groups", "result", "ratio", "sample_ratio", "retain_policy",
                "investigation_id", "raise_on_dispute", "code_field", "merge_key",
                "scopes", "sharing_scopes", "agreement_id"}}
            sample_set = source_sample(
                records if not isinstance(records, DedupResult) else None,
                config,
                result=records if isinstance(records, DedupResult) else None,
                center=center, credentials=credentials, scope=sharing_scope,
                **sample_kwargs)
            self.last_sharing_sample = sample_set
            return sample_set

        if config is None:
            config = self.sample_configs[0] if self.sample_configs else SampleConfig(
                plan_id="SAMP-AUTO", event_type_id="EVEN-0001", sample_ratio=1.0)
        # 采样
        threshold = max(1, int(len(records) * config.sample_ratio))
        sampled = list(records[:threshold])

        # 归并
        if config.merge_key:
            merged: dict[str, EventRecord] = {}
            for record in sampled:
                mkey = record.parsed_fields.get(config.merge_key, "")
                if not mkey:
                    continue
                existing = merged.get(mkey)
                if existing is None or record.event_time > existing.event_time:
                    merged[mkey] = record
            return list(merged.values())
        return sampled

    def sample_all(self, records: list[EventRecord]) -> list[EventRecord]:
        """按事件类型匹配采样配置批量采样归并。

        传入多源原行/去重组时走来源共享采样，返回 :class:`SampleSet`。
        """
        if self._records_are_source_like(records) or (
                records and isinstance(records[0], DedupGroup)):
            sample_set = source_sample(records, center=self.sharing_center)
            self.last_sharing_sample = sample_set
            return sample_set
        result: list[EventRecord] = []
        handled_type_ids: set[str] = set()
        for config in self.sample_configs:
            target_type_id = config.event_type_id
            target_records = [r for r in records if r.event_type.type_id == target_type_id]
            handled_type_ids.add(target_type_id)
            sampled = self.sample(target_records, config)
            result.extend(sampled)
        # 未匹配采样配置的事件保留原样
        for record in records:
            if record.event_type.type_id not in handled_type_ids:
                result.append(record)
        return result

    def get_stats(self) -> dict[str, dict[str, int]]:
        """获取去重规则统计数据。"""
        stats: dict[str, dict[str, int]] = {}
        for rule in self.dedup_rules:
            stats[rule.rule_id] = {
                "hit_count": rule.hit_count,
                "ignore_count": rule.ignore_count,
            }
        return stats

    def reset_fingerprints(self):
        """重置指纹缓存（窗口周期结束或测试隔离用）。"""
        self._fingerprint_store.clear()


def make_dedup_sample_pipeline() -> DedupSamplePipeline:
    """工厂函数：创建预配置的去重采样管道实例。"""
    return DedupSamplePipeline()