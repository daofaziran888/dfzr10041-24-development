# 多源日志：双方授权共享去重与采样归并

对应需求：只有经双方批准、明确同组的两个来源才能折叠相同请求码；采样按该范围
**实际领取各组唯一代表**，并通过样本原行保留各来源可核对位置；未授权归并按越权处理。

## 运行核对

```bash
cd backend
python verify_source_sharing.py          # 打印甲/乙/丙交错场景报告 + 27 项断言
python -m pytest tests/ -q               # 全部 76 项（含原有 49 项，零回归）
```

仅依赖标准库；`app/core/source_sharing.py` 可直接被系统 Python 3.11 导入。

## 入口与关键类型

| 职责 | API |
| --- | --- |
| 归组入口 | `app.core.source_sharing.deduplicate(lines, center=..., credentials=..., scope=...)` |
| 选样入口 | `app.core.source_sharing.sample(groups_or_lines, ...)` |
| 既有管道入口 | `DedupSamplePipeline.deduplicate(...)` / `.sample(...)`（旧三元组/list 契约不变；共享分支返回带 `.groups` 的 `DedupOutcome` 与 `SampleSet`） |
| 双方凭证 | `SourceCredential(source, partner, scope_id)`，两份互为对方、同 scope 的凭证匹配 |
| 共享范围 | `SharingScope("A","B")`（必须恰好两个来源；未授权直接用于归并会抛 `UnauthorizedMergeError`） |
| 授权中心 | `AuthorizationCenter`：`issue_credential` / `approve_pair`(`grant`) / `active_agreement(credentials=...)` / `revoke` / `can_read` / `fingerprint_for` / `read_lines` |
| 调查/领取/确认 | `SamplingOffice.open_investigation` → `Investigation.claim/reclaim/confirm`（或 `office.claim/confirm/run`） |
| 交付与恢复 | `office.deliver(...)` → 丢确认时抛 `DeliveryInterruptedError`；`office.verify_original_delivery(...)` / `office.recover(...)` |
| 原行位置 | `OriginalLine.ref()` → `LineRef{source,line_number,line_id,location,checksum,raw_line,content}` |
| 争议 | `Dispute`（全部 `refs/lines/digests` 保留），争议样本 `kind="dispute"` 且 `representative is None` |

## 需求 → 行为/测试对照

- **默认各一条 + 重传不多占格**：按 `(source, request_code)` 分组，原行身份
  `来源#L行号`（无行号用校验值），重传计入 `retransmissions` 但不新增组/格。
  测试 `TestDefaultPerSource`（含跨批次重传）。
- **只有明确同组的两个来源可折叠，C 独立**：授权 pair 才连边，第三方不参与。
  `TestBilateralScope.test_only_explicit_pair_folds_and_c_stays`。
- **越权**：未带生效双方协议的显式 scope → `UnauthorizedMergeError`；
  指纹/日志按 `can_read/fingerprint_for/read_lines` 放行，AB 凭证不能授权 C。
- **授权冲突按选定双方凭证**：同一来源对多份生效协议时无选择即报
  `AuthorizationConflictError`；传 `credentials=[ca, cb]` 精确选定。
- **内容矛盾**：共享组内容摘要不一致 → `disputed`，隔离进 `result.disputes`，
  样本不指定代表，甲乙证据全保留，丙仍独立。`TestDispute`。
- **领取后才授权的冲突**：`permission_conflicts()` 给提示；
  `confirm()` 默认 `keep_claims`（3 条，保留领取时 `source_local` 依据），
  或 `reclaim()` 按新凭证重领合成（AB 1 + C 1 = 2，旧领取置 `superseded` 留审计）。
  两种结果的每个样本都带 `PermissionBasis.describe()`，可交代当时权限。
- **并发确认只留一份**：`Investigation` 内置 `RLock` + 已固化短路，
  16 线程/Barrier 测试断言所有调用返回同一 `SampleSet`。
- **新调查按已批准范围合并 AB**：`TestConcurrencyAndNewInvestigation`。
- **撤销**：`center.revoke("A","B", by=...)` 后新调查回到 3 条 `source_local`；
  已确认/已交付的 `SampleSet.manifest()` 与权限依据快照不变。
- **交付中断/恢复**：`RecordingTransport(lose_ack=True)` 模拟“授权侧已收到但
  ack 丢失”。重复 `deliver` 同幂等键不重发；`recover` 先比对授权侧收件箱中的
  原 manifest 指纹：一致则补确认、不重发；授权侧确无原件才按**同一冻结
  manifest**（同批原行、同指纹）补发；撤销后传 `regroup=True` 重发被
  `ScopeRevokedError` 拒绝。
- **代表选择约定**：`deduplicate` 沿用既有“首见保留”；`sample` 沿用
  `SampleConfig.retain_policy="latest"` 的既有“最新事件”约定，可用
  `retain_policy="first"` 覆盖。无论谁当代表，`origin_refs` 都保留全组原行。

## 甲/乙/丙真实输入核对结论（脚本实际输出）

请求码 `REQ-7F3A-20261124-001`：

- 默认/冲突轮“各采一条”：3 个样本，代表分别来自
  甲 `:101`、乙 `:205`、丙 `:88`（甲 L101 的重传被幂等）。
- 批准 AB 后“重领合成”和“新调查并发确认”：均为 2 个样本——
  AB 共享样本证据为 `甲:101 + 乙:205`（latest 代表为乙 `:205`），
  丙样本仅 `丙:88`；`丙#L88` 从不进入 AB 样本，C 未被错误合并。
- 矛盾码 `REQ-9B2E-...-002`：甲 `:102`/乙 `:206` 进争议隔离，丙 `:89` 独立。
- A 撤销后新建调查：恢复为甲/乙/丙 3 条；已交付 manifest 仍是
  `[A#L101,B#L205]` 合并 + `[C#L88]`。
