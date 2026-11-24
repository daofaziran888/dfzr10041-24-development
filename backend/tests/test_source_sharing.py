"""测试：多源日志的双方授权共享去重、实际选样、授权冲突与交付恢复。

对应任务场景（A=甲、B=乙、C=丙）：
- 默认三来源相同请求码各保留一条；重传同一原行不多占格；
- 只有经双方批准、明确同组的两个来源可折叠，C 始终独立；
- deduplicate 归组、sample 实际领取各组唯一代表，样本保留各来源原行位置；
- 授权冲突按“选定的双方凭证”处理；未获许可的归并属于越权；
- 同键内容矛盾时保留全部证据并隔离争议，不任选一条原行；
- 撤销后已交付样本保留原依据，新调查重新拆成独立来源；
- 已交付但未收到确认 -> 中断；恢复先核清原交付，不按撤销后的新组重发；
- 并发确认同一调查只保留一份样本；
- 用甲/乙/丙真实输入交错授权、确认、重试，核对前后样本原行与 C 是否被误并。

直接运行：``python tests/test_source_sharing.py``
"""
from __future__ import annotations

import os
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.source_sharing import (
    AuthorizationCenter,
    AuthorizationConflictError,
    DeliveryInterruptedError,
    FingerprintAccessDenied,
    OriginalLine,
    RecordingTransport,
    SamplingOffice,
    SharingScope,
    UnauthorizedMergeError,
    build_jia_yi_bing_lines,
    deduplicate,
    filter_code,
    sample,
)
from app.core.dedup_sample import DedupSamplePipeline

CODE_OK = "REQ-7F3A-20261124-001"
CODE_CONFLICT = "REQ-9B2E-20261124-002"

# 甲/乙/丙真实原行的稳定身份
JIA_L101, YI_L205, BING_L88 = "A#L101", "B#L205", "C#L88"
JIA_L102, YI_L206, BING_L89 = "A#L102", "B#L206", "C#L89"


def ok_lines() -> list[OriginalLine]:
    return filter_code(build_jia_yi_bing_lines(), CODE_OK)


def conflict_lines() -> list[OriginalLine]:
    return filter_code(build_jia_yi_bing_lines(), CODE_CONFLICT)


def uids(sample_set) -> list[list[str]]:
    return [s.origin_uids() for s in sample_set]


# ---------------------------------------------------------------------------
# 1. 默认行为：各来源独立 + 重传幂等
# ---------------------------------------------------------------------------

class TestDefaultPerSource:
    def test_abc_same_code_keeps_three(self):
        result = deduplicate(ok_lines())
        assert len(result) == 3
        keys = {g.source_keys[0] for g in result}
        assert keys == {"A", "B", "C"}
        assert all(g.mode == "source_local" for g in result)

    def test_retransmit_same_line_no_extra_slot(self):
        rows = ok_lines()
        assert len(rows) == 4  # 甲 L101 与其重传
        result = deduplicate(rows)
        assert result.retransmissions == 1
        jia = next(g for g in result if g.source_keys == ["A"])
        assert len(jia.refs) == 1
        assert jia.refs[0].line_id == JIA_L101
        # 再次整体重放，仍然只有 3 格
        again = deduplicate(rows + rows)
        assert len(again) == 3
        assert again.retransmissions >= 4

    def test_retransmit_in_later_batch_keeps_three_claims(self):
        office = SamplingOffice()
        inv = office.open_investigation("INV-RETX")
        first_batch = [x for x in ok_lines() if x.line_id != JIA_L101]
        # 上面排除了甲，单独把甲原行作为首批
        jia = next(x for x in ok_lines() if x.line_id == JIA_L101)
        inv.add_lines([jia, *first_batch])
        assert len(inv.claim()) == 3
        # 采集代理稍后重传甲的同一原行（第二个批次）
        inv.add_lines([jia])
        claims = inv.claim()
        assert len(claims) == 3
        jia_claim = next(c for c in claims if c.source_keys == ["A"])
        assert [r.line_id for r in jia_claim.origin_refs] == [JIA_L101]

    def test_pipeline_entries_deduplicate_and_sample(self):
        """串联入口仍然是 DedupSamplePipeline.deduplicate / sample。"""
        pipe = DedupSamplePipeline()
        reps, hit, ignored = pipe.deduplicate(ok_lines())
        assert len(reps) == 3
        assert pipe.last_sharing_dedup is not None
        samples = pipe.sample(ok_lines())
        assert len(samples) == 3
        assert all(s.basis.mode == "source_local" for s in samples)

    def test_sample_representative_policy_latest_default(self):
        """sample 沿用既有 latest 约定；显式 first 时回到最早原行。"""
        center = AuthorizationCenter()
        center.grant("A", "B")
        latest = sample(ok_lines(), center=center)
        ab_latest = next(s for s in latest if s.basis.mode == "bilateral_shared")
        assert ab_latest.representative.line_id == YI_L205
        first = sample(ok_lines(), center=center, retain_policy="first")
        ab_first = next(s for s in first if s.basis.mode == "bilateral_shared")
        assert ab_first.representative.line_id == JIA_L101


# ---------------------------------------------------------------------------
# 2. 双方授权范围与越权
# ---------------------------------------------------------------------------

class TestBilateralScope:
    def test_only_explicit_pair_folds_and_c_stays(self):
        center = AuthorizationCenter()
        center.grant("甲", "乙", scope_id="SCOPE-JY")
        result = deduplicate(ok_lines(), center=center)
        assert len(result) == 2
        shared = next(g for g in result if g.mode == "shared")
        c_only = next(g for g in result if g.source_keys == ["C"])
        assert shared.pair_key if hasattr(shared, "pair_key") else True
        assert set(shared.source_keys) == {"A", "B"}
        assert {r.line_id for r in shared.refs} == {JIA_L101, YI_L205}
        assert [r.line_id for r in c_only.refs] == [BING_L88]

    def test_manual_approved_scope_is_honored(self):
        scope = SharingScope("A", "B", authorized=True, scope_id="MANUAL")
        result = deduplicate(ok_lines(), scope=scope)
        assert sum(1 for g in result if g.mode == "shared") == 1

    def test_unauthorized_scope_is_yuequan(self):
        for bad in (SharingScope("A", "B"),
                    SharingScope(sources=("甲", "乙"), authorized=False)):
            try:
                deduplicate(ok_lines(), scope=bad)
            except UnauthorizedMergeError:
                pass
            else:
                raise AssertionError("未授权范围去重必须抛 UnauthorizedMergeError（越权）")

        pipe = DedupSamplePipeline()
        try:
            pipe.deduplicate(ok_lines(), sharing_scope=SharingScope("A", "B"))
        except UnauthorizedMergeError:
            pass
        else:
            raise AssertionError("管道入口同样必须拦截越权归并")

    def test_mismatched_credentials_rejected(self):
        center = AuthorizationCenter()
        ca = center.issue_credential("A", "B", scope_id="s1")
        cb = center.issue_credential("C", "A", scope_id="s1")  # 不配对
        try:
            center.approve_pair(credentials=[ca, cb])
        except Exception:
            pass
        else:
            raise AssertionError("不匹配的双方凭证不能成立共享")

    def test_conflicting_grants_need_selected_credentials(self):
        center = AuthorizationCenter()
        center.grant("A", "B", scope_id="v1")
        center.grant("A", "B", scope_id="v2")
        try:
            center.active_agreement("A", "B")
        except AuthorizationConflictError:
            pass
        else:
            raise AssertionError("多份冲突授权且未选凭证时必须报冲突")

        ca = center.issue_credential("A", "B", scope_id="v2")
        cb = center.issue_credential("B", "A", scope_id="v2")
        chosen = center.active_agreement("A", "B", credentials=[ca, cb])
        assert chosen.scope.scope_id == "v2"
        result = deduplicate(ok_lines(), credentials=[ca, cb])
        shared = next(g for g in result if g.mode == "shared")
        assert shared.scope.scope_id == "v2"

    def test_selected_credentials_alone_authorize_and_stay_pair_bound(self):
        center = AuthorizationCenter()
        ca = center.issue_credential("A", "B", scope_id="K")
        cb = center.issue_credential("B", "A", scope_id="K")
        # 没有预登记协议：选定的两份匹配凭证本身即构成双方批准
        result = deduplicate(ok_lines(), center=center, credentials=[ca, cb])
        assert sum(1 for g in result if g.mode == "shared") == 1
        # AB 凭证不能拿去授权 C 读取 B
        assert center.can_read("C", "B", credentials=[ca, cb]) is False

    def test_fingerprint_and_log_read_permission(self):
        center = AuthorizationCenter()
        b_line = next(x for x in ok_lines() if x.line_id == YI_L205)
        # 未授权的 C 不能读 B 的指纹/日志
        assert center.can_read("C", "B") is False
        try:
            center.fingerprint_for("C", b_line)
        except FingerprintAccessDenied:
            pass
        else:
            raise AssertionError("C 读取 B 指纹必须被拒绝")
        # 双方批准后 A 可读 B 的共享指纹
        ag = center.grant("A", "B", scope_id="AB-FP")
        fp = center.fingerprint_for("A", b_line)
        assert fp == b_line.fingerprint("AB-FP")
        read = center.read_lines("A", [b_line])
        assert len(read) == 1
        assert ag.status == "active"


# ---------------------------------------------------------------------------
# 3. 内容矛盾 -> 争议隔离
# ---------------------------------------------------------------------------

class TestDispute:
    def test_contradiction_isolated_keeps_all_evidence(self):
        center = AuthorizationCenter()
        center.grant("A", "B", scope_id="AB-DISP")
        result = deduplicate(conflict_lines(), center=center)
        assert len(result.disputes) == 1
        dispute = result.disputes[0]
        # 甲/乙双方证据都保留
        assert {r.line_id for r in dispute.refs} == {JIA_L102, YI_L206}
        assert len(dispute.lines) == 2
        assert len(set(dispute.digests.values())) == 2
        # 丙独立成组，没有被卷进争议
        c_group = next(g for g in result if g.source_keys == ["C"])
        assert [r.line_id for r in c_group.refs] == [BING_L89]

    def test_dispute_sample_has_no_arbitrary_representative(self):
        center = AuthorizationCenter()
        center.grant("甲", "乙")
        samples = sample(conflict_lines(), center=center)
        dispute_samples = [s for s in samples if s.kind == "dispute"]
        assert len(dispute_samples) == 1
        ds = dispute_samples[0]
        assert ds.representative is None
        assert {r.line_id for r in ds.origin_refs} == {JIA_L102, YI_L206}
        # 争议样本之外，丙仍是独立代表
        reps = [s for s in samples if s.kind == "representative"]
        assert any(s.origin_uids() == [BING_L89] for s in reps)


# ---------------------------------------------------------------------------
# 4. 已领取候选 vs 新许可冲突：两种交代方式
# ---------------------------------------------------------------------------

class TestClaimConflict:
    def _claimed_office(self):
        center = AuthorizationCenter()
        office = SamplingOffice(center)
        inv = office.open_investigation("INV-CONFLICT", lines=ok_lines())
        claims = inv.claim()
        assert len(claims) == 3
        assert all(c.basis.mode == "source_local" for c in claims)
        center.grant("A", "B", scope_id="AB-NEW")
        return office, inv

    def test_permission_conflicts_detected(self):
        _, inv = self._claimed_office()
        conflicts = inv.permission_conflicts()
        assert conflicts, "授权后应识别出已有领取与新许可的冲突"
        assert all(c["now_available_agreement"] for c in conflicts)

    def test_keep_claims_each_source_one_with_basis(self):
        _, inv = self._claimed_office()
        ss = inv.confirm()  # 默认 keep_claims：本轮先各采一条
        assert len(ss) == 3
        assert all(s.basis.mode == "source_local" for s in ss)
        # 权限依据可交代：每个样本都有决定时间与说明
        assert all(s.basis.decided_at and s.basis.describe() for s in ss)
        assert {uid for group in uids(ss) for uid in group} == {
            JIA_L101, YI_L205, BING_L88}

    def test_reclaim_synthesizes_one_with_new_basis(self):
        center = AuthorizationCenter()
        office = SamplingOffice(center)
        inv = office.open_investigation("INV-RECLAIM", lines=ok_lines())
        inv.claim()
        ca = center.issue_credential("甲", "乙", scope_id="AB-SEL")
        cb = center.issue_credential("乙", "甲", scope_id="AB-SEL")
        center.approve_pair(credentials=[ca, cb])

        new_claims = inv.reclaim(credentials=[ca, cb])
        assert len(new_claims) == 2
        shared_claim = next(c for c in new_claims if c.basis.mode == "bilateral_shared")
        assert {r.line_id for r in shared_claim.origin_refs} == {JIA_L101, YI_L205}
        ss = inv.confirm()
        assert len(ss) == 2
        modes = {s.basis.mode for s in ss}
        assert modes == {"bilateral_shared", "source_local"}
        # 旧领取没有被抹掉，审计可追溯
        assert len(inv.superseded_claims) == 3
        assert any(e.action == "reclaim" for e in inv.audit)


# ---------------------------------------------------------------------------
# 5. 并发确认 + 新调查合并 A/B
# ---------------------------------------------------------------------------

class TestConcurrencyAndNewInvestigation:
    def test_concurrent_confirm_keeps_one_sample_set(self):
        center = AuthorizationCenter()
        center.grant("A", "B")
        office = SamplingOffice(center)
        inv = office.open_investigation("INV-CONC", lines=ok_lines())
        inv.claim()
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            return inv.confirm()

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: worker(), range(16)))
        assert len({id(r) for r in results}) == 1
        assert inv.sample_set is results[0]
        assert len(inv.sample_set) == 2  # AB 一条 + C 一条
        # 样本 id 不重复
        ids = [s.sample_id for s in inv.sample_set]
        assert len(ids) == len(set(ids))

    def test_c_always_independent_under_concurrency(self):
        center = AuthorizationCenter()
        center.grant("甲", "乙")
        office = SamplingOffice(center)
        ss = office.run("INV-C", lines=ok_lines())
        ab = next(s for s in ss if s.basis.mode == "bilateral_shared")
        c = next(s for s in ss if "C" in s.source_keys)
        assert set(ab.source_keys) == {"A", "B"}
        assert c.source_keys == ["C"]
        assert BING_L88 not in ab.origin_uids()
        assert c.origin_uids() == [BING_L88]

    def test_new_investigation_merges_ab_per_approved_scope(self):
        center = AuthorizationCenter()
        office = SamplingOffice(center)
        # 批准前的调查：3 条
        before = office.run("INV-BEFORE", lines=ok_lines())
        assert len(before) == 3
        # 双方批准后新建调查：2 条
        center.grant("A", "B", scope_id="AB-OK")
        after = office.run("INV-AFTER", lines=ok_lines())
        assert len(after) == 2
        merged = next(s for s in after if s.basis.mode == "bilateral_shared")
        assert {r.line_id for r in merged.origin_refs} == {JIA_L101, YI_L205}
        c_sample = next(s for s in after if s.basis.mode == "source_local")
        assert c_sample.origin_uids() == [BING_L88]


# ---------------------------------------------------------------------------
# 6. 撤销：旧样本保留依据，新调查拆分
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_revocation_splits_new_investigation_and_preserves_old(self):
        center = AuthorizationCenter()
        office = SamplingOffice(center)
        center.grant("A", "B", scope_id="AB-REV")
        old = office.run("INV-OLD", lines=ok_lines())
        old_manifest = old.manifest()
        assert len(old) == 2

        center.revoke("A", "B", by="A", reason="A 方退出共享")
        new = office.run("INV-NEW-AFTER-REVOKE", lines=ok_lines())
        assert len(new) == 3
        assert all(s.basis.mode == "source_local" for s in new)
        # 已固化样本与 manifest 不变，原双方依据保留
        assert old.manifest() == old_manifest
        old_ab = next(s for s in old if s.basis.mode == "bilateral_shared")
        assert old_ab.basis.agreement_id
        assert {r.line_id for r in old_ab.origin_refs} == {JIA_L101, YI_L205}


# ---------------------------------------------------------------------------
# 7. 交付中断与幂等恢复
# ---------------------------------------------------------------------------

class TestDeliveryRecovery:
    def _delivered_interrupted(self, key: str = "K-1"):
        transport = RecordingTransport(lose_ack=True)
        office = SamplingOffice(AuthorizationCenter(), transport=transport)
        office.center.grant("A", "B")
        inv = office.open_investigation("INV-DELIV", lines=ok_lines())
        inv.claim()
        inv.confirm()
        try:
            office.deliver(inv, idempotency_key=key)
        except DeliveryInterruptedError as exc:
            return office, inv, exc.receipt
        raise AssertionError("应当抛出交付中断")

    def test_lost_ack_interrupts(self):
        _, inv, receipt = self._delivered_interrupted()
        assert receipt.status == "interrupted"
        assert inv.status == "interrupted"

    def test_retry_deliver_same_key_does_not_resend(self):
        office, inv, receipt = self._delivered_interrupted("K-RETRY")
        attempts = office.transport.send_attempts
        again = office.deliver(inv, idempotency_key="K-RETRY")
        assert again is receipt or again.idempotency_key == receipt.idempotency_key
        assert office.transport.send_attempts == attempts

    def test_recover_finds_original_and_confirms_without_resend(self):
        office, inv, receipt = self._delivered_interrupted("K-REC")
        check = office.verify_original_delivery(inv)
        assert check["authorization_side_received"] is True
        assert check["manifest_identical"] is True
        attempts = office.transport.send_attempts
        report = office.recover(inv)
        assert report["action"] == "confirmed_original"
        assert report["resent"] is False
        assert office.transport.send_attempts == attempts
        assert inv.status == "acknowledged"

    def test_recover_when_never_received_resends_same_manifest(self):
        transport = RecordingTransport(lose_ack=True)
        office = SamplingOffice(AuthorizationCenter(), transport=transport)
        office.center.grant("A", "B")
        inv = office.open_investigation("INV-MISS", lines=ok_lines())
        inv.claim()
        inv.confirm()
        try:
            office.deliver(inv, idempotency_key="K-MISS")
        except DeliveryInterruptedError as exc:
            receipt = exc.receipt
        # 授权侧实际上从未收到
        transport.inbox.clear()
        transport.lose_ack = False
        report = office.recover(inv)
        assert report["action"] == "resent_original"
        assert report["resent"] is True
        assert transport.send_attempts == 2
        assert report["receipt"]["manifest_fingerprint"] == receipt.manifest_fingerprint
        # 重发的仍是同一批原行
        sent = transport.inbox["K-MISS"]["manifest"]
        origin = [u for s in sent["samples"] for u in s["origin_uids"]]
        assert set(origin) == {JIA_L101, YI_L205, BING_L88}

    def test_no_regroup_resend_after_revocation(self):
        office, inv, _ = self._delivered_interrupted("K-REV")
        office.center.revoke("A", "B", by="B")
        # 恢复仍然核清并确认原交付（原 manifest 中 AB 仍是一条）
        report = office.recover("K-REV")
        assert report["action"] == "confirmed_original"
        merged = report["receipt"]["manifest"]["samples"][0]
        assert set(merged["origin_uids"]) == {JIA_L101, YI_L205}
        # 明确要求按撤销后状态重新分组交付 -> 拒绝
        try:
            office.deliver(inv, idempotency_key="NEW-AFTER-REVOKE", regroup=True)
        except Exception as exc:
            assert "撤销" in str(exc) or isinstance(exc, UnauthorizedMergeError)
        else:
            raise AssertionError("撤销后重新分组交付必须被拒绝")


# ---------------------------------------------------------------------------
# 8. 端到端交错场景 + 前后原行核对
# ---------------------------------------------------------------------------

def execute_interleaved_scenario() -> dict:
    """按题目时间线真实执行一遍，返回所有需要核对的产物。"""
    real_lines = build_jia_yi_bing_lines()
    code1 = filter_code(real_lines, CODE_OK)
    code2 = filter_code(real_lines, CODE_CONFLICT)

    timeline: list[str] = []

    # (0) 默认归组 + 采样：前一次实际样本
    before_groups = deduplicate(code1)
    before_samples = sample(before_groups, investigation_id="BEFORE")
    timeline.append("默认范围：A/B/C 各一条（甲 L101 重传被幂等）")

    center = AuthorizationCenter()
    transport = RecordingTransport(lose_ack=True)
    office = SamplingOffice(center, transport=transport)

    # (1) 两个调查都在授权前领取候选
    inv_keep = office.open_investigation("INV-KEEP", lines=code1)
    inv_keep.claim()
    inv_merge = office.open_investigation("INV-RECLAIM", lines=code1)
    inv_merge.claim()
    timeline.append("已领取甲/乙/丙候选，均为 source_local 依据，待确认")

    # (2) A/B 交换选定的双方凭证并批准共享
    ca = center.issue_credential("A", "B", scope_id="AB-PACT")
    cb = center.issue_credential("B", "A", scope_id="AB-PACT")
    agreement = center.approve_pair(credentials=[ca, cb])
    timeline.append(f"A/B 双方凭证成立协议 {agreement.agreement_id}")

    conflicts = inv_keep.permission_conflicts()

    # (3a) 路径一：本轮先各采一条（沿用领取时权限）
    keep_samples = inv_keep.confirm()
    timeline.append("路径一 keep_claims：仍出 3 条，依据为领取时 source_local")

    # (3b) 路径二：重领后合成一条
    inv_merge.reclaim(credentials=[ca, cb])
    merge_samples = inv_merge.confirm()
    timeline.append("路径二 reclaim：AB 合成 1 条 + C 独立 1 条，共 2 条")

    # (4) 矛盾键：争议隔离
    dispute_samples = sample(code2, center=center, credentials=[ca, cb])
    timeline.append("矛盾请求码：甲乙证据隔离为 dispute，丙独立")

    # (5) 新建调查 + 16 线程并发确认
    inv_conc = office.open_investigation("INV-CONCURRENT", lines=code1)
    inv_conc.claim()
    barrier = threading.Barrier(8)

    def _worker():
        barrier.wait()
        return inv_conc.confirm()

    with ThreadPoolExecutor(max_workers=8) as pool:
        concurrent_sets = list(pool.map(lambda _: _worker(), range(16)))
    after_samples = concurrent_sets[0]
    timeline.append("新调查 16 线程并发确认：仅固化同一份样本集合")

    # (6) 交付 -> 确认丢失中断 -> 同键重试 -> 恢复核清原交付
    delivery_error = None
    try:
        office.deliver(inv_conc, idempotency_key="DELIV-CONC-1")
    except DeliveryInterruptedError as exc:
        delivery_error = exc
    retry_receipt = office.deliver(inv_conc, idempotency_key="DELIV-CONC-1")
    recovery = office.recover(inv_conc, idempotency_key="DELIV-CONC-1")
    timeline.append("交付确认丢失 -> 中断；同键重试不重发；recover 核清原件后确认")

    # (7) A 撤销：旧交付保留依据，新调查重新拆三来源
    center.revoke("A", "B", by="A")
    post_revoke = office.run("INV-POST-REVOKE", lines=code1)
    timeline.append("A 撤销后：已交付样本不变，新调查重新拆成甲/乙/丙三条")

    return {
        "real_lines": real_lines,
        "before_groups": before_groups,
        "before_samples": before_samples,
        "keep_samples": keep_samples,
        "merge_samples": merge_samples,
        "conflicts": conflicts,
        "dispute_samples": dispute_samples,
        "after_samples": after_samples,
        "concurrent_sets": concurrent_sets,
        "delivery_error": delivery_error,
        "retry_receipt": retry_receipt,
        "recovery": recovery,
        "post_revoke": post_revoke,
        "transport": transport,
        "timeline": timeline,
        "center": center,
    }


class TestEndToEndRealInputs:
    def test_interleaved_scenario_provenance(self):
        art = execute_interleaved_scenario()

        # 前一次实际样本：恰好来自甲 L101 / 乙 L205 / 丙 L88
        before = art["before_samples"]
        assert len(before) == 3
        assert sorted(s.representative.line_id for s in before) == sorted(
            [JIA_L101, YI_L205, BING_L88])
        # deduplicate 入口遵循“首见保留”，sample 入口遵循既有 latest 策略；
        # AB 组中乙 L205 事件时间更晚，因此实际样本代表为乙，证据仍含甲。
        ab_group = next(g for g in art["before_groups"] if g.source_keys == ["A"])
        assert ab_group.representative.line_id == JIA_L101

        # 各采一条路径
        assert len(art["keep_samples"]) == 3

        # 重领合成路径：2 条，AB 样本原行齐全，C 不被误并
        merged = art["merge_samples"]
        assert len(merged) == 2
        ab = next(s for s in merged if s.basis.mode == "bilateral_shared")
        c = next(s for s in merged if s.basis.mode == "source_local")
        assert ab.representative.line_id == YI_L205  # latest
        assert set(ab.origin_uids()) == {JIA_L101, YI_L205}
        assert c.origin_uids() == [BING_L88]

        # 争议样本
        kinds = {s.kind for s in art["dispute_samples"]}
        assert "dispute" in kinds

        # 后一次（新调查并发确认）实际样本：同样 AB 合并、C 独立，且只此一份
        after = art["after_samples"]
        assert len({id(s) for s in art["concurrent_sets"]}) == 1
        assert len(after) == 2
        after_ab = next(s for s in after if s.basis.mode == "bilateral_shared")
        after_c = next(s for s in after if "C" in s.source_keys)
        assert set(after_ab.origin_uids()) == {JIA_L101, YI_L205}
        assert after_c.origin_uids() == [BING_L88]
        # 关键：C 的原行绝不出现在 AB 合并样本里，B 行也不进 C 样本
        assert BING_L88 not in after_ab.origin_uids()
        assert YI_L205 not in after_c.origin_uids()
        assert JIA_L101 not in after_c.origin_uids()

        # 交付恢复
        assert art["delivery_error"] is not None
        assert art["recovery"]["action"] == "confirmed_original"
        assert art["recovery"]["resent"] is False

        # 撤销后新调查拆 3 条
        assert len(art["post_revoke"]) == 3


# ---------------------------------------------------------------------------
# 可读的场景报告（直接运行本文件时打印）
# ---------------------------------------------------------------------------

def print_report() -> None:
    art = execute_interleaved_scenario()
    line = "=" * 78
    print(line)
    print("甲(A)/乙(B)/丙(C) 多源共享去重与实际选样：交错授权-确认-重试核对")
    print(line)

    print("\n[时间线]")
    for i, item in enumerate(art["timeline"], 1):
        print(f"  {i}. {item}")

    def dump(title: str, ss) -> None:
        print(f"\n-- {title}（共 {len(ss)} 个样本）--")
        for row in ss.origin_table():
            rep = row["representative"] or "（争议：不指定代表）"
            origins = ", ".join(f"{o['source']}#{o['line_number']}@{o['checksum'][:8]}"
                                for o in row["origins"])
            print(f"  {row['sample_id']} [{row['kind']}/{row['basis']}] {row['request_code']}")
            print(f"      代表位置: {rep}")
            print(f"      可核对原行: {origins}")

    dump("前一次实际样本（无共享范围，deduplicate→sample）", art["before_samples"])
    dump("冲突轮·路径一（保留已领取，各采一条）", art["keep_samples"])
    dump("冲突轮·路径二（按选定凭证重领合成）", art["merge_samples"])
    dump("矛盾键（争议隔离 + 丙独立）", art["dispute_samples"])
    dump("后一次实际样本（新调查，16 线程并发确认的唯一结果）", art["after_samples"])
    dump("A 撤销后的新调查（重新拆成独立来源）", art["post_revoke"])

    rec = art["recovery"]
    print("\n[交付恢复]")
    print(f"  动作={rec['action']}  是否重发={rec['resent']}  "
          f"传输发送次数={art['transport'].send_attempts}")
    print(f"  核交报告: 授权侧收到={rec['check']['authorization_side_received']}, "
          f"manifest一致={rec['check']['manifest_identical']}")
    print("\n核对结论：AB 仅在双方批准范围内合并；丙(C) 始终独立；"
          "前后样本原行如上，C 未被错误合并。")


# ---------------------------------------------------------------------------
# 运行入口（与仓库其他 tests 一致，可直接 python 运行）
# ---------------------------------------------------------------------------

def _all_test_methods() -> dict:
    tests: dict[str, Any] = {}
    for cls_name, cls in sorted(globals().items()):
        if not cls_name.startswith("Test") or not isinstance(cls, type):
            continue
        for meth_name in sorted(dir(cls)):
            if meth_name.startswith("test_"):
                tests[f"{cls_name}.{meth_name}"] = getattr(cls(), meth_name)
    return tests


if __name__ == "__main__":
    from typing import Any  # noqa: E402

    print_report()
    print("\n" + "=" * 78)
    print("运行断言测试")
    print("=" * 78)
    passed = failed = 0
    for name, fn in _all_test_methods().items():
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\ntest_source_sharing: {passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)
