# Sentinella v4.0 — 架构重设计交付报告

> 交付日期：2026-04-08
> 分支：main
> 测试：527 通过 (520 单元 + 7 集成)
> 代码变更：13,374 行新增 / 1,041 行修改，涉及 90 个文件

---

## 一、项目概述

基于《泛化架构优化计划》(OPTIMIZATION_PLAN.md) 和《持续学习架构设计》(KNOWLEDGE_BASE_ARCHITECTURE.md)，对 Sentinella 静态分析工具进行全栈架构重设计，从 P0 到 P9 共 10 个阶段并行实施，目标将误报率从 80-98% 降至 <5%。

---

## 二、阶段交付清单

### P0：Evidence 模型 + Finding Identity + 状态持久化
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/evidence.rs` | 439 | EvidenceKind 枚举、EvidenceStore (DashMap)、EvidenceResult 四级判定 |
| `src/state.rs` | 520 | ProjectState + FindingRecord + FindingStatus 持久化 (.sentinella/state.json) |
| `src/scanners/types.rs` | 176 | Confidence 枚举 (Suspect/Likely/Confirmed)、stable_id() 哈希、normalize_message() |
| `src/reporters/gap.rs` | +153 | min_confidence 过滤、Confidence 显示集成 |

**测试**: 26 个单元测试

---

### P1：Rule Pack 系统 (YAML 声明式规则引擎)
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/rule_pack/schema.rs` | 263 | RulePack、ProtectionEvidenceRule、DataSourceRule、RuleLifecycle |
| `src/rule_pack/loader.rs` | 465 | 4层加载 (project > user > community > builtin)，include_str! 嵌入 |
| `src/rule_pack/engine.rs` | 309 | Regex 规则执行引擎，生成 Evidence 写入 EvidenceStore |
| `src/rule_pack/detect.rs` | 335 | 自动技术栈检测 (package.json/requirements.txt/go.mod/Cargo.toml/pom.xml/Gemfile/composer.json) |
| `src/rule_pack/validator.rs` | 337 | 规则包校验器 (正则/confidence/kind/lifecycle) |

**测试**: 33 个测试 (引擎 17 + 加载器 10 + 校验 6)

---

### P2-A：3 层抑制系统
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/suppress.rs` | 685 | SuppressionSet (行内注释)、SuppressConfig (配置文件)、DismissFile (交互式) |

- 行内注释：`// sentinella-ignore`、`// sentinella-disable S7`
- 配置抑制：`.sentinella.yaml` 中 suppress 段
- 交互式：`sentinella dismiss <id> --reason "..."`

**测试**: 20 个单元测试

---

### P2-B：上下文记忆
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/memory.rs` | 732 | MemoryFile、MemoryEffect、NLP 关键词解析、3级作用域 |

- 存储：`.sentinella/memories.yaml`
- CLI：`sentinella memory add "auth在API Gateway层" --scanner S7`
- 效果：自动调整匹配 finding 的 severity/confidence

**测试**: 16 个单元测试

---

### P3：贝叶斯校准
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/calibration.rs` | 505 | CalibrationStore、BucketEntry (alpha/beta)、Beta 分布后验 |

- 按 scanner:extension 分桶 (如 `S7:*.ts`)
- 内置先验从审计数据初始化
- CLI：`sentinella triage` 交互式标注 (confirm/dismiss)

**测试**: 8 个单元测试

---

### P4：Scanner 配置化
| 文件 | 说明 |
|------|------|
| `src/config/schema.rs` | ScannerOverrides + 9 个 per-scanner 配置结构体 |
| `.sentinella.yaml.example` | 完整配置文档 |
| 5 个 scanner 文件 | S7, S11, S18, S22, S23 从硬编码改为配置驱动 |

---

### P5：模式挖掘
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/pattern_miner.rs` | 660 | 聚类已 dismiss 的 FP，按 scanner+文件模式分组，生成抑制建议 |

- CLI：`sentinella learn` — 分析 state.json 中的 FP 记录
- 输出：SuggestedSuppression + SuggestedRuleException

**测试**: 12 个单元测试

---

### P6：规则生命周期
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/rule_lifecycle.rs` | 314 | LifecyclePolicy 过滤器、lifecycle summary |

- 三阶段：Experimental → Stable → Deprecated
- CLI 标志：`--experimental`、`--include-deprecated`
- YAML 中每条规则可标注 lifecycle + since_version + deprecated_reason

**测试**: 8 个单元测试

---

### P7：跨扫描器关联
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/correlation.rs` | 431 | CorrelationGroup、correlate_findings()、apply_correlation() |

- 同文件 ±10 行内多扫描器命中 → 互证提升置信度
- 2 个扫描器：Suspect→Likely / Likely→Confirmed
- 3+ 个扫描器：直接 Confirmed
- CLI：`--no-correlation` 可关闭

**测试**: 11 个单元测试

---

### P8：校准数据迁移
| 文件 | 行数 | 说明 |
|------|------|------|
| `src/calibration_transfer.rs` | 408 | ExportedCalibration、import/export、weight 控制合并强度 |

- CLI：`sentinella calibrate export/import/show`
- JSON 格式，可跨团队共享 FP 率知识

**测试**: 9 个单元测试

---

### P9：跨平台扩展 + 社区生态

#### 13 个内置框架规则包
| 语言 | 框架 | protection 规则数 | data-source 规则数 |
|------|------|-------------------|-------------------|
| TypeScript | NestJS | 6 | 3 |
| TypeScript | Express | 7 | 4 |
| Python | FastAPI | 4 | 3 |
| Python | Django | 7 | 3 |
| Python | Flask | 5 | 3 |
| Go | Gin | 4 | 3 |
| Go | Echo | 6 | 3 |
| Go | Chi | 6 | 3 |
| Java/Kotlin | Spring Boot | 6 | 3 |
| Ruby | Rails | 6 | 3 |
| PHP | Laravel | 6 | 3 |
| Rust | Actix | 6 | 3 |
| Rust | Axum | 6 | 3 |

#### Pack CLI
| 子命令 | 功能 |
|--------|------|
| `sentinella pack list` | 列出所有规则包 (builtin/user/project/community) |
| `sentinella pack validate <file>` | 校验 YAML 规则包结构 |
| `sentinella pack install <file>` | 安装规则包到项目或全局 |

#### 社区规则包支持
- 4 层优先级加载：project > user > community > builtin
- 加载时自动校验 (regex 合法性、confidence 范围、lifecycle 完整性)
- `~/.sentinella/rules/community/` 目录支持

**测试**: 23 个 (pack_manager 12 + validator 10 + loader 1)

---

## 三、CLI 子命令总览

| 命令 | 功能 |
|------|------|
| `sentinella check` | 运行扫描 (支持 --min-confidence, --experimental, --no-correlation) |
| `sentinella init` | 生成配置文件 |
| `sentinella dispatch` | 派发任务到 Notion/GitHub/stdout |
| `sentinella dismiss <id>` | 标记 finding 为误报 |
| `sentinella memory add/list` | 管理项目上下文记忆 |
| `sentinella triage` | 交互式标注 finding (confirm/dismiss) |
| `sentinella learn` | 挖掘 FP 模式，建议抑制规则 |
| `sentinella calibrate export/import/show` | 校准数据跨项目迁移 |
| `sentinella pack list/validate/install` | 规则包管理 |

---

## 四、数据处理管道 (Check Pipeline)

```
输入代码 → 索引 (Indexer)
         → 规则包执行 (Rule Engine → EvidenceStore)
         → 27 扫描器运行 (Scanners)
         → 抑制过滤 (Suppress: inline + config + dismiss)
         → 贝叶斯校准 (Calibration: alpha/beta)
         → 跨扫描器关联 (Correlation: ±10行互证)
         → 置信度过滤 (min_confidence / show_suspect)
         → 输出 (Terminal / JSON / Markdown / Notion)
```

---

## 五、预期误报率改善

| 阶段 | 误报率 | 关键机制 |
|------|--------|---------|
| 基线 | 80-98% | 27 个扫描器无上下文 |
| P0+P1 | ~30% | Evidence 模型 + 框架感知规则包 |
| P2 | ~15% | 3 层抑制 + 上下文记忆 |
| P3+P4 | ~5% | 贝叶斯校准 + 可配置阈值 |
| P5-P9 | <2% | 模式挖掘 + 跨扫描器关联 + 社区先验 |

---

## 六、代码统计

| 指标 | 数值 |
|------|------|
| Rust 源文件 | 73 个 |
| Rust 代码行数 | 32,379 行 |
| YAML 规则包 | 13 个 (2,117 行) |
| 单元测试 | 520 个 |
| 集成测试 | 7 个 |
| 新增代码 | +13,374 行 |
| 修改代码 | -1,041 行 |
| Git 提交 | 56 个 |
| 涉及文件 | 90 个 |

---

## 七、新增模块清单

| 模块 | 路径 | 行数 |
|------|------|------|
| Evidence 模型 | `src/evidence.rs` | 439 |
| 状态持久化 | `src/state.rs` | 520 |
| 抑制系统 | `src/suppress.rs` | 685 |
| 上下文记忆 | `src/memory.rs` | 732 |
| 贝叶斯校准 | `src/calibration.rs` | 505 |
| 校准迁移 | `src/calibration_transfer.rs` | 408 |
| 模式挖掘 | `src/pattern_miner.rs` | 660 |
| 规则生命周期 | `src/rule_lifecycle.rs` | 314 |
| 跨扫描器关联 | `src/correlation.rs` | 431 |
| 规则包管理 | `src/pack_manager.rs` | 507 |
| Rule Pack 引擎 | `src/rule_pack/` (5文件) | 1,709 |
| **合计** | | **6,910** |
