# Sentinella Knowledge Base — 持续学习架构设计

## 〇、问题本质

Rule Pack 解决了"框架知识外部化"，但仍然是 **manually curated** — 每种误报模式都需要人手写规则。用户的真实需求是：

> 当下次遇到新的误报或真实错误时，系统能从反馈中自动学习，越用越准。

这不是一个规则引擎问题，而是一个 **知识积累与泛化** 问题。

---

## 一、参考架构对比

| 系统 | 反馈模型 | 学习机制 | 泛化机制 | Sentinella 可借鉴 |
|------|---------|---------|---------|-----------------|
| SpamAssassin | ham/spam 标签 | Bayesian token 概率更新 | auto-learn-on-error (仅学习系统判错的) | 双轨打分 + 贝叶斯校准 |
| Semgrep | triage 决策 + 自然语言 | LLM 提取 Memory → 注入 triage 上下文 | 三级作用域: 项目/规则/漏洞类 | Context Memory 声明式上下文 |
| SonarQube | Open/FP/Accepted/Fixed | 不自动学习; 人工调 Quality Profile | Profile 继承链 | Finding 生命周期 + 持久化 |
| Sigma | falsepositives 字段 + status | 社区 PR + status 晋升 | experimental → test → stable | Rule 成熟度生命周期 |
| Falco | Exception tuples | 每日自动生成 exception 建议, 人审批 | Rule/Exception 分离, append 覆盖 | 结构化 Exception 系统 |
| Active Learning | 不确定性采样 | 选最不确定的让人标注 → 更新模型 | 特征空间决策边界学习 | 优先展示低置信 finding |
| Bayesian Rule Lists | alpha/beta 计数器 | 每个 verdict 更新后验概率 | per-context bucket 细粒度校准 | 最简可行的自动校准 |

**核心洞察：** 不需要训练 ML 模型。用 **贝叶斯计数器 + 模式聚类 + Context Memory** 就可以实现 90% 的持续学习效果，且完全可解释、可调试。

---

## 二、Knowledge Base 总体架构

```
                    ┌─────────────────────────┐
                    │     sentinella check     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Rule Pack Engine      │  ← YAML 规则包 (框架知识)
                    │    (Phase 1 已设计)       │
                    └────────────┬────────────┘
                                 │ 产出 Finding[]
                    ┌────────────▼────────────┐
            ┌──────►│   Knowledge Base Filter  │◄──────┐
            │       └────────────┬────────────┘       │
            │                    │                     │
   ┌────────┴────────┐  ┌───────▼───────┐  ┌─────────┴────────┐
   │  Context Memory  │  │ Finding State │  │ Bayesian Priors  │
   │  (声明式上下文)   │  │ (生命周期)     │  │ (置信度校准)      │
   │                  │  │               │  │                  │
   │  "本项目用 RLS"   │  │ Open          │  │ S7+*.controller  │
   │  "auth 在 GW 层" │  │ Confirmed     │  │   α=12, β=340    │
   │  "S12 不适用"     │  │ FalsePositive │  │   conf=0.034     │
   │                  │  │ Accepted      │  │                  │
   │                  │  │ Fixed         │  │ S1+*.tsx         │
   │                  │  │               │  │   α=5, β=280     │
   └────────┬────────┘  └───────┬───────┘  │   conf=0.018     │
            │                    │          └─────────┬────────┘
            │                    │                     │
            │           ┌───────▼───────┐             │
            │           │ Pattern Miner │◄────────────┘
            │           │ (模式提取)     │
            │           └───────┬───────┘
            │                    │ 聚类相似 FP →
            │                    │ 建议新规则/exception
            │           ┌───────▼───────┐
            └───────────│ Rule Suggester│
                        │ (规则建议)     │
                        └───────────────┘

反馈入口:
  sentinella triage          ← 交互式标注
  sentinella learn           ← 从历史标注中提取模式
  sentinella memory add      ← 添加项目上下文
  // sentinella-ignore       ← inline 标注
```

---

## 三、六大组件详细设计

### 3.1 Finding Identity — 让 Finding 可追踪

**当前问题：** `Finding` 没有稳定 ID，每次扫描都是全新的，无法跨 run 追踪。

**设计：**

```rust
impl Finding {
    /// 生成确定性 ID: hash(scanner + relative_path + normalized_message)
    /// 不含 line number — 因为代码移动后行号变化，但 finding 本质相同
    pub fn stable_id(&self, root: &Path) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.scanner.as_bytes());
        if let Some(ref file) = self.file {
            let rel = file.strip_prefix(root).unwrap_or(file);
            hasher.update(rel.to_string_lossy().as_bytes());
        }
        // 归一化 message: 去掉行号、具体值，保留结构
        hasher.update(self.normalize_message().as_bytes());
        let hash = hasher.finalize();
        format!("{}-{}", self.scanner, &hash.to_hex()[..8])
    }

    fn normalize_message(&self) -> String {
        // "GET /api/orders has no auth" → "METHOD PATH has no auth"
        // 去掉变化的部分，保留不变的模式
        let re = Regex::new(r"(GET|POST|PUT|PATCH|DELETE)\s+\S+").unwrap();
        re.replace_all(&self.message, "METHOD PATH").to_string()
    }
}
```

**文件存储：** `.sentinella/state.json`

```json
{
  "version": 1,
  "last_scan": "2026-04-07T10:30:00Z",
  "findings": {
    "S7-a3f2b1c0": {
      "status": "false_positive",
      "scanner": "S7",
      "file": "src/orders/orders.controller.ts",
      "message_pattern": "METHOD PATH has no auth",
      "first_seen": "2026-04-01",
      "labeled_at": "2026-04-06",
      "labeled_by": "kd",
      "reason": "class-level @UseGuards",
      "tags": ["nestjs", "class-decorator"]
    },
    "S12-7e8d4a2b": {
      "status": "confirmed",
      "scanner": "S12",
      "file": "src/db/schema.sql",
      "first_seen": "2026-04-01",
      "labeled_at": "2026-04-02",
      "fixed_at": "2026-04-03"
    }
  }
}
```

### 3.2 Context Memory — 声明式项目上下文

**灵感来源：Semgrep Assistant Memories**

用户写一句话描述项目特征，系统自动据此调整 scanner 行为。

**三级作用域：**

```yaml
# .sentinella/memories.yaml

# Level 1: 项目级 — 影响所有 scanner
project:
  - "本项目使用 Supabase RLS 实现租户隔离，所有表都有 user_id 列和 RLS policy"
  - "认证统一在 API Gateway (Kong) 层处理，后端服务不需要自己做 auth middleware"
  - "所有 DELETE 操作都是软删除（设置 deleted_at），不需要 2FA 确认"
  - "日志使用统一脱敏中间件 LogSanitizer，所有敏感字段自动 mask"

# Level 2: Scanner 级 — 影响特定 scanner
scanners:
  S7:
    - "本项目 auth 由 NestJS 类级 @UseGuards(JwtAuthGuard) 统一处理"
    - "以下端点设计上是公开的：/health, /api/auth/login, /api/auth/register"
  S12:
    - "SQL 使用 schema-qualified 表名（如 oms.order_line），不是裸表名"
    - "_prisma_migrations 和 spatial_ref_sys 是系统表，不需要审计"
  S1:
    - "前端页面通过自定义 hook (use*) 间接调用 API，不直接使用 fetch/axios"
  S17:
    - "Go 代码中 _ = xxx.Close() 是标准清理模式，不是错误吞没"

# Level 3: Pattern 级 — 影响特定代码模式
patterns:
  - match: "**/*.controller.ts"
    memory: "所有 controller 继承 BaseController，已有类级 guard"
  - match: "**/contracts/sdk/**"
    memory: "这是类型定义包，不包含实际端点，不应被 S8/S26 扫描"
```

**系统如何使用 Memory：**

Memory 不是自由文本 — 它被解析为结构化的 **Evidence Override**：

```rust
struct MemoryEffect {
    scope: MemoryScope,          // Project | Scanner(id) | Pattern(glob)
    effect: MemoryEffectType,
}

enum MemoryEffectType {
    /// 声明某类保护已存在 → 对应 scanner 的 finding confidence 降低
    ProtectionDeclared {
        kind: EvidenceKind,      // auth, rate-limit, audit, ...
        confidence_override: f64, // 0.0 = 完全信任声明, 1.0 = 忽略声明
    },
    /// 声明某些文件/表不适用于某 scanner → 等效于 exclude
    NotApplicable {
        scanner: String,
        file_patterns: Vec<String>,
    },
    /// 声明某种代码模式是安全的 → 匹配时标记为 safe-ignore
    SafePattern {
        regex: String,
        reason: String,
    },
}
```

**关键设计决策：Memory 是可验证的。**

```bash
$ sentinella memory validate
[OK] "auth 在 API Gateway 层" — 找到 kong.yml 中的 auth plugin 配置
[WARN] "所有表都有 RLS policy" — 发现 3 张表缺少 RLS policy
[OK] "controller 有类级 guard" — 12/14 controller 确认有 @UseGuards
[STALE] "使用 LogSanitizer" — 未找到 LogSanitizer 引用，可能已重命名
```

### 3.3 Bayesian Confidence Calibration — 越用越准的置信度

**灵感来源：SpamAssassin Bayes + Bayesian Rule Lists**

**核心思想：** 为每个 (scanner, context_bucket) 维护一个 Beta 分布后验，从用户反馈中自动校准。

```
context_bucket = scanner_id + file_glob_pattern

例如:
  S7 + "*.controller.ts"    → α=2, β=200   → confidence = 1.0%  (几乎全是误报)
  S7 + "*.py"                → α=50, β=10   → confidence = 83%   (大多是真问题)
  S12 + "*.sql"              → α=3, β=90    → confidence = 3.2%  (schema.table 问题)
  S17 + "*.go"               → α=20, β=80   → confidence = 20%   (Go 的 _ = err)
  S13 + "**/api/**"          → α=5, β=45    → confidence = 10%   (DELETE 2FA)
```

**存储：** `.sentinella/calibration.json`

```json
{
  "version": 1,
  "buckets": {
    "S7:*.controller.ts": { "alpha": 2, "beta": 200, "last_update": "2026-04-06" },
    "S7:*.py":            { "alpha": 50, "beta": 10, "last_update": "2026-04-06" },
    "S12:*.sql":          { "alpha": 3, "beta": 90, "last_update": "2026-04-06" },
    "S17:*.go":           { "alpha": 20, "beta": 80, "last_update": "2026-04-06" },
    "S1:*.tsx":           { "alpha": 5, "beta": 280, "last_update": "2026-04-06" }
  },
  "global_priors": {
    "S7":  { "alpha": 1, "beta": 1 },
    "S12": { "alpha": 1, "beta": 1 },
    "S1":  { "alpha": 1, "beta": 1 }
  }
}
```

**更新规则（受 SpamAssassin auto-learn-on-error 启发）：**

```rust
fn update_calibration(bucket: &str, verdict: Verdict) {
    let entry = calibration.get_or_create(bucket, default_prior());
    match verdict {
        Verdict::Confirmed   => entry.alpha += 1,  // 真阳性
        Verdict::FalsePositive => entry.beta += 1,  // 误报
        Verdict::Accepted    => {},                 // 用户接受风险, 不更新模型
        Verdict::Fixed       => entry.alpha += 1,  // 被修复 = 是真问题
    }
}

fn confidence(bucket: &str) -> f64 {
    let entry = calibration.get(bucket).unwrap_or(default_prior());
    entry.alpha as f64 / (entry.alpha + entry.beta) as f64
}
```

**关键守护机制：**

1. **Auto-learn-on-error only** — 只在用户主动纠错时更新，不从未标注的 finding 学习
2. **最低样本量** — alpha + beta < 5 时使用全局 prior，避免小样本过拟合
3. **时间衰减** — 超过 90 天未更新的 bucket，alpha/beta 各乘 0.9 衰减
4. **上下文桶自动发现** — 初始桶为 `scanner_id:*`，当某个文件模式的校准值与全局偏差 > 30% 时自动裂变为更细的桶

### 3.4 Pattern Miner — 从反馈中发现规则

**核心问题：** 用户标注了 200 条 S7 误报，都在 `*.controller.ts` 文件中 — 系统应能自动发现这个模式并建议一条 rule。

**算法：**

```
输入: 近期标注为 FalsePositive 的 Finding[]
输出: 候选 Rule/Exception 建议[]

Step 1: 按 scanner 分组
Step 2: 对每组, 提取特征向量
  - file_extension: ".ts", ".py", ".go", ...
  - file_pattern: "*.controller.ts", "*.service.ts", ...
  - path_segment: "controllers/", "middleware/", "contracts/", ...
  - message_pattern: normalized message template
  - co_occurring_scanners: 同文件被哪些其他 scanner 标记

Step 3: 聚类 (简单的 group-by, 不需要 ML)
  - 如果同一 (scanner, file_pattern) 的 FP 率 > 80% 且样本 >= 5:
    → 建议 exception rule

Step 4: 生成候选规则
```

**交互式输出：**

```bash
$ sentinella learn

Analyzing 342 labeled findings...

╭──────────────────────────────────────────────────────────────╮
│  Pattern #1: S7 on *.controller.ts — 97% false positive     │
│  (198/204 findings labeled FP)                               │
│                                                              │
│  Root cause: NestJS class-level @UseGuards not detected      │
│                                                              │
│  Suggested action (pick one):                                │
│  [A] Add memory:                                             │
│      "NestJS controller 文件使用类级 @UseGuards 保护"         │
│  [B] Add exception to .sentinella.yaml:                      │
│      exceptions:                                             │
│        S7:                                                   │
│          - name: nestjs_class_guard                           │
│            fields: [file_pattern]                             │
│            values: ["*.controller.ts"]                        │
│  [C] Add rule pack enhancement (PR to rules/nestjs.yaml)     │
│  [D] Skip                                                    │
╰──────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────────────╮
│  Pattern #2: S12 on *.sql with schema-prefix — 100% FP      │
│  (94/94 findings labeled FP)                                 │
│                                                              │
│  Root cause: Table names use schema.table format             │
│                                                              │
│  Suggested action:                                           │
│  [A] Add memory:                                             │
│      "SQL 使用 schema-qualified 表名 (oms.xxx, scm.xxx)"     │
│  [B] Add config:                                             │
│      data_isolation:                                         │
│        schema_prefix: [oms, scm, tms, crm, audit, iam]      │
│  [C] Skip                                                    │
╰──────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────────────╮
│  Pattern #3: S1 on *.tsx — 95% FP                            │
│  (266/280 findings labeled FP)                               │
│                                                              │
│  Common trait: Files import custom hooks (use*)              │
│  that internally call API — S1 doesn't trace hook chain      │
│                                                              │
│  Suggested action:                                           │
│  [A] Add memory:                                             │
│      "前端页面通过 use* hook 间接调用 API"                     │
│  [B] Add data_source_evidence rule to rule pack              │
│  [C] Skip                                                    │
╰──────────────────────────────────────────────────────────────╯

Applied 2 memories, 1 config change.
Updated calibration for 3 buckets.
```

### 3.5 Rule Lifecycle — 规则成熟度管理

**灵感来源：Sigma status 字段**

```yaml
# 规则包中每条 rule 有 status 字段
protection_evidence:
  - name: nestjs-class-guard
    status: stable         # experimental | testing | stable | deprecated
    since: "2026-04-01"
    false_positive_scenarios:
      - "全局 APP_GUARD 通过 module provider 注入时，decorator 不出现在 controller 文件中"
      - "动态 guard（基于数据库配置）无法通过 AST 静态检测"
```

**Status 对扫描行为的影响：**

| Status | 默认输出 | CI 阻断 | Confidence 权重 |
|--------|---------|---------|---------------|
| experimental | 仅 `--show-experimental` | 不阻断 | × 0.5 |
| testing | 显示, 标记 [TESTING] | 不阻断 | × 0.75 |
| stable | 正常显示 | 可阻断 | × 1.0 |
| deprecated | 仅 `--show-deprecated` | 不阻断 | × 0.25 |

**晋升条件（可配置）：**

```yaml
# .sentinella.yaml
rule_lifecycle:
  promote_to_testing:
    min_scans: 5
    min_true_positives: 3
  promote_to_stable:
    min_scans: 20
    min_confidence: 0.70
    min_true_positives: 10
  auto_deprecate:
    max_false_positive_rate: 0.95
    min_samples: 20
```

### 3.6 Cross-Scanner Correlation — 交叉验证

**灵感来源：SpamAssassin 3+3 规则（至少需要 header 和 body 各 3 分）**

```rust
/// 如果多个 scanner 在同一文件/同一端点都报出问题 → 提升 confidence
/// 如果只有一个 scanner 报出，且该 scanner 在此 context 历史 FP 率高 → 降低 confidence
fn adjust_confidence_by_correlation(findings: &mut [Finding]) {
    // 按文件分组
    let by_file: HashMap<PathBuf, Vec<&Finding>> = group_by_file(findings);

    for (file, file_findings) in &by_file {
        let scanner_count = file_findings.iter()
            .map(|f| &f.scanner)
            .collect::<HashSet<_>>()
            .len();

        for finding in file_findings {
            if scanner_count >= 3 {
                // 3+ scanner 交叉验证 → confidence boost
                finding.confidence = (finding.confidence * 1.3).min(0.99);
            } else if scanner_count == 1 {
                // 孤证 → 如果该 scanner 在此 context 历史 FP 率 > 50%, 降级
                let bucket_conf = calibration.confidence(&finding.scanner, file);
                if bucket_conf < 0.5 {
                    finding.confidence *= 0.6; // 大幅降低
                }
            }
        }
    }
}
```

---

## 四、完整工作流：从误报到学习

### 首次扫描（冷启动）

```bash
$ sentinella check
# 无历史数据, 使用默认 prior (α=1, β=1, conf=50%)
# 所有 finding 标记为 Likely (中置信度)

[S7] Likely  GET /orders has no auth  (confidence: 50%)
[S7] Likely  POST /users has no auth  (confidence: 50%)
[S12] Likely  Ghost table: order_line  (confidence: 50%)
...
6,080 findings (0 Confirmed, 6080 Likely, 0 Suspect)
```

### 第一轮标注

```bash
$ sentinella triage
# 优先展示最不确定的 findings (uncertainty sampling)
# 用户标注: Confirmed (真问题) / FalsePositive / Accepted (接受风险)

S7-a3f2b1c0: GET /orders has no auth → [F] False Positive
  reason? > class-level @UseGuards
S7-b2e1c3d4: POST /users has no auth → [F] False Positive
  reason? > class-level @UseGuards
...
(标注 50 条后)

Labeled 50 findings. Updating calibration...
  S7:*.controller.ts  α=2, β=48  → confidence: 4.0%
  S12:*.sql           α=0, β=20  → confidence: 0.0%

Patterns detected:
  [!] S7 on *.controller.ts: 96% FP (48/50)
  Suggest: Add memory "NestJS controller 使用类级 guard" → [y/n]?
```

### 第二次扫描（已有校准数据）

```bash
$ sentinella check
# 使用校准后的 confidence

[S7] Suspect  GET /orders has no auth  (confidence: 4%)   ← 降级为 Suspect
[S7] Suspect  POST /orders has no auth (confidence: 4%)
[S12] Suspect Ghost table: order_line   (confidence: 0%)
[S26] Confirmed  refresh 未吊销旧 token  (confidence: 89%)  ← 真问题突出

790 findings:
  15 Confirmed  ← 真实问题, 需要修复
  120 Likely    ← 需要人工确认
  5,945 Suspect ← 大概率误报, 默认隐藏

Default output shows 135 findings (Confirmed + Likely only).
Use --show-suspect to see all 6,080.
```

### 持续迭代

```bash
# 每次扫描后, 标注少量 finding
$ sentinella triage --batch 20   # 每次标注 20 条

# 定期提取模式
$ sentinella learn               # 从累计标注中建议规则

# 导出校准数据给团队共享
$ sentinella calibration export > team-calibration.json

# 其他项目导入校准数据 (同技术栈可复用)
$ sentinella calibration import team-calibration.json --merge
```

---

## 五、数据模型总览

```
.sentinella/
├── memories.yaml          # Context Memory (用户声明的项目上下文)
├── state.json             # Finding State (每个 finding 的生命周期状态)
├── calibration.json       # Bayesian Priors (per-bucket α/β 计数器)
├── ignore.yaml            # Dismiss Records (交互式标记的误报)
└── rules/                 # 项目级自定义规则包
    └── custom.yaml

~/.sentinella/
├── rules/                 # 全局规则包
│   ├── builtin/
│   │   ├── express.yaml
│   │   ├── nestjs.yaml
│   │   └── ...
│   └── community/
├── calibration/           # 跨项目校准数据
│   ├── nestjs.json        # 同技术栈项目可共享
│   └── fastapi.json
└── config.yaml            # 全局配置
```

### 知识的生命周期

```
观察          标注          校准            泛化           固化
Finding  →  Verdict   →  Calibration  →  Pattern   →  Rule/Memory
(扫描产出)   (用户标注)    (贝叶斯更新)    (聚类发现)    (持久化知识)

          ╭──── 人工介入 ────╮   ╭── 自动 ──╮   ╭── 半自动 ──╮
          │                  │   │          │   │            │
     ┌────▼────┐        ┌───▼───▼──┐   ┌──▼───▼──┐   ┌────▼────┐
     │ triage  │        │calibrate │   │  learn  │   │ memory  │
     │ command │        │  engine  │   │ command │   │   add   │
     └─────────┘        └──────────┘   └─────────┘   └─────────┘
```

---

## 六、与 Rule Pack 的关系

Knowledge Base 不替代 Rule Pack，而是在其上层构建：

```
Layer 4: Knowledge Base (学习层)
  — Context Memory, Bayesian Calibration, Pattern Mining
  — 从反馈中自动改进
  — 跨项目可迁移

Layer 3: Suppress System (抑制层)
  — Inline ignore, config exclude, dismiss
  — 用户手动消除已知误报

Layer 2: Rule Pack Engine (规则层)
  — YAML 规则包, 框架知识声明
  — 支持新框架无需改代码

Layer 1: Core Engine (引擎层)
  — tree-sitter AST, regex, 跨文件追踪
  — 框架无关的扫描基础设施

Layer 0: Indexer (索引层)
  — 文件发现, 并行解析, DashMap 存储
```

**关键区别：**

| | Rule Pack | Knowledge Base |
|---|---|---|
| 知识来源 | 人工编写 YAML | 从用户反馈中自动提取 |
| 更新方式 | 编辑文件, 提交 PR | `sentinella triage` + `sentinella learn` |
| 生效时机 | 下次扫描 | 即时 (校准) / 下次扫描 (规则) |
| 可共享范围 | 同框架的所有项目 | 同技术栈 + 类似架构的项目 |
| 知识类型 | "如何检测" (how) | "什么是误报" (what) + "为什么" (why) |

---

## 七、实现路线图（在 Rule Pack Phase 之后）

| Phase | 内容 | 工作量 | 依赖 |
|-------|------|--------|------|
| KB-0 | Finding Identity + state.json 持久化 | 1 周 | Phase 0 (Evidence Model) |
| KB-1 | Context Memory 基础 — memories.yaml + validate | 1 周 | KB-0 |
| KB-2 | Bayesian Calibration — calibration.json + 自动更新 | 1-2 周 | KB-0 |
| KB-3 | `sentinella triage` 交互式标注命令 | 1 周 | KB-0 + KB-2 |
| KB-4 | Pattern Miner + `sentinella learn` | 2 周 | KB-3 |
| KB-5 | Rule Lifecycle (experimental/stable/deprecated) | 1 周 | Phase 1 (Rule Pack) |
| KB-6 | Cross-Scanner Correlation | 1 周 | KB-2 |
| KB-7 | 跨项目校准导入/导出 | 1 周 | KB-2 |

**总投入：约 8-10 周（与 Rule Pack Phase 可部分并行）。**

---

## 八、冷启动策略

新项目第一次用 Sentinella，没有任何反馈数据，怎么办？

### 策略 1: 内置先验 (Built-in Priors)

基于三次审计数据，为已知高 FP 场景预设 prior：

```json
{
  "builtin_priors": {
    "S7:*.controller.ts":  { "alpha": 1, "beta": 20, "note": "NestJS class guard 常被遗漏" },
    "S7:*.py":             { "alpha": 5, "beta": 5,  "note": "Python auth 检测尚不完善" },
    "S12:*.sql":           { "alpha": 1, "beta": 10, "note": "schema-qualified 表名常见" },
    "S1:*.tsx":            { "alpha": 1, "beta": 15, "note": "React hook 链常被遗漏" }
  }
}
```

### 策略 2: 技术栈 Prior Transfer

如果检测到技术栈与某个共享校准文件匹配，自动加载：

```bash
$ sentinella check
[INFO] Detected: NestJS + Next.js
[INFO] Loading community priors for nestjs (based on 12 projects, 8,400 labeled findings)
[INFO] S7 initial confidence on *.controller.ts: 5% (community prior)
```

### 策略 3: 首次扫描引导式标注

```bash
$ sentinella check --first-run
# 首次运行时, 随机抽样 20 条 finding 让用户快速标注
# 用 5 分钟标注就可以初始化校准数据

Quick calibration (5 min): Label 20 findings to improve accuracy.
[1/20] S7: GET /orders has no auth
  [C]onfirmed  [F]alse positive  [S]kip? > F
[2/20] S12: Ghost table: order_line
  [C]onfirmed  [F]alse positive  [S]kip? > F
...
Calibration initialized! Next scan will show calibrated confidence scores.
```

---

## 九、设计原则总结

| # | 原则 | 说明 |
|---|------|------|
| 1 | **反馈即学习** | 每次用户标注都更新系统知识，无需额外"训练"步骤 |
| 2 | **可解释优先** | 贝叶斯计数器完全透明；Pattern Miner 输出人可读的聚类；不用黑盒 ML |
| 3 | **最小标注负担** | 不要求标注所有 finding；uncertainty sampling 优先展示最有价值的 |
| 4 | **知识可迁移** | calibration.json 可跨项目共享（同技术栈）；memories 可复制到类似项目 |
| 5 | **渐进增强** | 冷启动用 built-in prior → 首次标注初始化 → 持续迭代越用越准 |
| 6 | **人始终掌控** | Pattern Miner 只建议，不自动应用；Memory validate 验证但不强制 |
| 7 | **Auto-learn-on-error** | 只从用户纠错中学习，不从未标注数据自我强化（防止正反馈循环） |
