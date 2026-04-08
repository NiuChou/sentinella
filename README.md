# Sentinella

**System completeness audit tool** — detect stub code, cross-layer gaps, API contract drift, and generate task breakdowns.

**系统完整性审计工具** — 检测残留桩代码、跨层断裂、API 契约漂移，并自动生成任务拆解。

---

<p align="center">
  <strong>English</strong> | <a href="#中文文档">中文文档</a>
</p>

---

## What is Sentinella?

Sentinella is a static analysis tool that scans your entire project — backend, BFF, hooks, pages, database, deployment configs — and reports **what's missing, what's broken, and what's drifted**. It goes beyond linting: it understands your system architecture and checks that every layer is properly connected.

### Key Capabilities

- **28 specialized scanners** covering stubs, security, deployment, API contracts, events, env vars, data isolation, auth security, doc-fact drift, and more
- **Tree-sitter AST parsing** for TypeScript, Python, and Go — no regex guessing
- **Cross-layer tracing** from database to API to frontend page
- **5-layer parallel execution** using Rayon for maximum performance
- **Evidence-based check pipeline** — scan → suppress → memory → calibrate → correlate → filter → render → state sync
- **Rule packs & lifecycle** — installable YAML rule packs with experimental/deprecated lifecycle filtering
- **Task dispatch** to Notion or GitHub Issues for actionable follow-up
- **Single binary, zero runtime dependencies** — `< 15MB` release build

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/NiuChou/sentinella.git
cd sentinella

# Build release binary
cargo build --release

# The binary is at target/release/sentinella
# Optionally, install it globally:
cargo install --path .
```

### Requirements

- Rust 1.75+ (edition 2021)
- No external runtime dependencies

## Quick Start

```bash
# 1. Generate a starter config
sentinella init --type fullstack

# 2. Edit .sentinella.yaml to match your project structure
# 3. Run the audit
sentinella check

# 4. Run specific scanners only
sentinella check --scanner S1,S6

# 5. Fail CI if score < 80
sentinella check --min_coverage 80

# 6. Export as JSON
sentinella check --format json

# 7. Generate tasks and dispatch to stdout
sentinella dispatch
```

## CLI Reference

```
sentinella [--config <PATH>] <COMMAND>
```

### Global Flags

| Flag | Description |
|------|-------------|
| `--config <PATH>` | Override config file auto-discovery |

### Commands

#### `sentinella check`

Run completeness scanners against the project.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir <PATH>` | `-d` | `.` | Project root directory |
| `--scanner <IDS>` | `-s` | all | Filter scanners (e.g., `S1,S9`) |
| `--format <FMT>` | `-f` | `terminal` | Output: `terminal`, `json`, `markdown`, `notion` |
| `--min_coverage <N>` | | | Exit non-zero if score < N |

#### `sentinella init`

Generate a starter `.sentinella.yaml` config file.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--type <TYPE>` | `-t` | `fullstack` | Template: `fullstack`, `backend-only`, `monorepo` |

#### `sentinella dispatch`

Generate task breakdowns and dispatch them.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir <PATH>` | `-d` | `.` | Project root directory |
| `--target <TARGET>` | `-t` | `stdout` | Target: `stdout`, `notion`, `github` |
| `--dry-run` | | `false` | Preview without sending |

#### `sentinella pack`

Manage YAML rule packs (built-in and community).

| Subcommand | Description |
|------------|-------------|
| `pack list` | List all available rule packs (built-in + community) |
| `pack validate <PATH>` | Validate a rule pack YAML file |
| `pack install <PATH>` | Install a community rule pack |

Built-in packs: `echo`, `chi`, `actix`, `axum`, `django`, `flask`, `spring-boot`, `rails`, `laravel`

## Scanners

Sentinella includes 28 scanners organized into 5 execution layers:

### Layer 1 — Base Detection

| ID | Scanner | What it detects |
|----|---------|-----------------|
| **S1** | Stub Detector | Frontend pages/hooks that use hardcoded data instead of real API connections |
| **S6** | Residue Finder | TODO, FIXME, HACK, mock data, and placeholder residue across the codebase |
| **S17** | Silent Error Swallowing | Empty catch blocks, ignored Promise rejections, swallowed exceptions |
| **S20** | Sensitive Data Logging | Passwords, tokens, secrets, OTP codes logged in console/logger calls |
| **S25** | Test Bypass Detection | Hardcoded test accounts, master passwords, debug flags bypassing auth flows |

### Layer 2 — Core Tracing

| ID | Scanner | What it detects |
|----|---------|-----------------|
| **S2** | Cross-Layer Tracer | Missing connections in the backend → BFF → hooks → page chain |
| **S9** | API Contract Drift | Frontend API calls that don't match any backend route definition |

### Layer 3 — Completeness

| ID | Scanner | What it detects |
|----|---------|-----------------|
| **S3** | Flow Analyzer | Broken business flows where API endpoints exist but pages don't import them |
| **S4** | Deploy Readiness | Dockerfiles missing healthchecks, unpinned base images, running as root |
| **S7** | Security Completeness | API endpoints not protected by auth middleware (auth, guard, jwt, session) |
| **S8** | Integration Test Coverage | Database tables without integration tests covering read/write/assert |
| **S12** | Data Isolation Audit | Ghost tables, inactive RLS policies, missing tenant filters, cache-only persistence, hardcoded credentials |
| **S13** | Destructive Endpoint Safety | DELETE/dangerous endpoints lacking confirmation, soft-delete, or audit trails |
| **S14** | Soft Delete Lifecycle | Missing soft-delete filtered queries, no reactivation path, or PII not cleared |
| **S16** | Role Hardcoding | Hardcoded role strings instead of using centralized role constants or enums |
| **S18** | Token Invalidation | State-changing operations (logout, suspend, delete) without token/session invalidation |
| **S19** | OTP Replay Protection | OTP verification endpoints lacking replay protection or rate limiting |
| **S21** | Insecure Token Storage | Auth tokens stored in localStorage/sessionStorage instead of httpOnly cookies |
| **S22** | Rate Limiting Coverage | Authentication endpoints missing rate limiting protection (brute-force risk) |
| **S26** | Refresh Token Rotation | Refresh token endpoints that issue new tokens without revoking old ones |
| **S27** | Race Condition Safety | Auth-path database writes (INSERT/UPSERT) without concurrency protection |

### Layer 4 — Drift Detection

| ID | Scanner | What it detects |
|----|---------|-----------------|
| **S10** | Event Schema Drift | Event topics produced but never consumed (or vice versa) |
| **S11** | Env Config Drift | Environment variables referenced in code but missing from deploy configs |
| **S15** | Cross-Service Duplication | Duplicate business logic across services in monorepo projects |
| **S23** | Audit Log Completeness | State-changing operations (login, DELETE, PUT, PATCH) without audit log calls |
| **S24** | Missing Uniqueness | SQL WHERE equality lookup columns lacking UNIQUE constraints |
| **S28** | Doc-Fact Drift | README/doc claims that contradict actual code (ports, deps, versions, images, env vars) |

### Layer 5 — Project

| ID | Scanner | What it detects |
|----|---------|-----------------|
| **S5** | Plan Drift | Deviation between your Notion project plan and the actual codebase |

> Layers execute sequentially; scanners within each layer run **in parallel** via Rayon.

### S12 Data Isolation Audit — Detection Rules

S12 implements **10 detection rules** across 3 dimensions to verify data-layer isolation:

#### Dimension A: Schema-Code Alignment

| Rule | ID | Severity | What it detects |
|------|----|----------|-----------------|
| Ghost Table | D1 | Critical | Migration defines `CREATE TABLE` but no application code writes to it |
| RLS Not Activated | D2 | Critical | RLS policy uses `current_setting('app.XXX')` but application code never calls `SET LOCAL` |
| ENABLE Without FORCE | D3 | Warning | `ENABLE ROW LEVEL SECURITY` found but no `FORCE ROW LEVEL SECURITY` — table owner bypasses RLS |

#### Dimension B: Query Isolation

| Rule | ID | Severity | What it detects |
|------|----|----------|-----------------|
| Missing Ownership Filter | D4 | Warning | Write endpoint (POST/PUT/DELETE) queries a user-scoped table without tenant column filter |
| IDOR-Prone GET | D5 | Info | GET endpoint returns records by ID without tenant filter on an RLS-protected table |

#### Dimension C: Infrastructure Isolation

| Rule | ID | Severity | What it detects |
|------|----|----------|-----------------|
| Cache-Only Persistence | D6 | Warning | Data written to Redis with TTL but no corresponding DB write in the same context |
| Default Credential | D7 | Critical | Hardcoded credential values (`password`, `secret`, `key`, `token`) that should use env vars |
| Dual-Pool Detection | D8 | Warning | Dual-Pool Detection — user-facing code uses admin DB pool instead of restricted RLS-aware pool |
| Redis Key Enumeration | D9 | Warning | Redis Key Enumeration — session-scoped keys without user_id prefix are enumerable |
| Cross-Service Data Leak | D10 | Warning | Cross-Service Data Leak — service directly queries tables owned by another service in monorepo |

> For the full implementation plan and scoring model, see `docs/S12-data-isolation-audit-plan.md`.

## Configuration

Sentinella looks for `.sentinella.yaml` in the project root (or parent directories). Use `--config` to specify a custom path.

### Minimal Config

```yaml
version: "1.0"
project: my-app
type: fullstack

layers:
  backend:
    pattern: "src/server/**/*.ts"

output:
  format: terminal
  min_coverage: 80
  severity: warning
```

### Full Config Reference

```yaml
version: "1.0"
project: my-fullstack-app
type: fullstack                # fullstack | backend-only | monorepo

# Layer definitions — map logical layers to file patterns
layers:
  backend:
    pattern: "src/server/**/*.ts"
    api_pattern: "src/server/routes/**/*.ts"
    stub_indicators:            # Strings that mark code as stub
      - "TODO"
      - "FIXME"
      - "STUB"
      - "PLACEHOLDER"
      - "not implemented"
    real_data_indicators:       # Strings that mark code as wired to real data
      - "prisma."
      - "db."
      - "fetch("
  bff:
    pattern: "src/api/**/*.ts"
  hooks:
    pattern: "src/hooks/**/*.ts"
  pages:
    pattern: "src/pages/**/*.tsx"

# Module cross-layer mapping (used by S2 Cross-Layer Tracer)
modules:
  - name: auth
    backend: "src/server/auth"
    bff: "src/api/auth"
    hooks: "src/hooks/useAuth.ts"
    page: "src/pages/login.tsx"

# Business flows (used by S3 Flow Analyzer)
flows:
  - name: user-login
    steps:
      - action: submit-credentials
        api: POST /api/auth/login
        page: src/pages/login.tsx
      - action: fetch-profile
        api: GET /api/users/me
        page: src/pages/dashboard.tsx

# Deploy readiness (used by S4)
deploy:
  dockerfile_pattern: "**/Dockerfile"
  require_healthcheck: true
  require_pinned_deps: true
  require_dockerignore: true

# Integration test coverage (used by S8)
integration_tests:
  enabled: true
  migrations_pattern: "db/migrations/**/*.sql"
  tests_pattern: "tests/integration/**/*.test.ts"
  exclude_tables:
    - _prisma_migrations
  require_rls_alignment: true
  min_coverage: 80

# Event alignment (used by S10)
events:
  producer_patterns:
    - "src/server/events/producers/**/*.ts"
  consumer_patterns:
    - "src/server/events/consumers/**/*.ts"

# Data isolation (used by S12)
data_isolation:
  enabled: true
  tenant_column: "user_id"
  tenant_column_aliases:
    - "owner_id"
    - "project_id"
  rls_session_var: "app.current_user_id"
  exclude_tables:
    - _prisma_migrations
    - schema_migrations
    - spatial_ref_sys
  exclude_redis_patterns:
    - "jwt:blacklist:*"
    - "ratelimit:*"
  admin_roles:
    - service_admin
  credential_keys:
    - password
    - secret
    - api_key
    - access_key
    - token

# Env var completeness (used by S11)
env:
  code_patterns:
    - "src/**/*.ts"
  deploy_patterns:
    - "docker-compose*.yml"
    - ".github/workflows/*.yml"
  env_example: ".env.example"

# Output settings
output:
  format: terminal              # terminal | json | markdown | notion
  min_coverage: 80
  severity: warning             # warning | error

# Task dispatch
dispatch:
  target: stdout                # stdout | notion | github
  notion_database_id: "..."     # Required for notion target
  github_repo: "owner/repo"    # Required for github target
  auto_assign: false
```

## Architecture

```
sentinella/
├── src/
│   ├── main.rs                  # CLI entrypoint (clap)
│   ├── config/                  # YAML config loading & schema
│   ├── indexer/                 # File indexing & AST parsing
│   │   ├── store.rs             # DashMap-based concurrent index
│   │   ├── types.rs             # ApiEndpoint, EnvRef, ImportEdge, ...
│   │   ├── parsers/             # Language-specific parsers
│   │   │   ├── typescript.rs    # tree-sitter + regex
│   │   │   ├── python.rs        # tree-sitter + regex
│   │   │   ├── go_lang.rs       # tree-sitter + regex
│   │   │   ├── sql.rs           # Regex-based DDL parsing
│   │   │   ├── dockerfile.rs    # Dockerfile instruction analysis
│   │   │   ├── env_file.rs      # .env file parsing
│   │   │   ├── yaml_config.rs   # docker-compose / k8s env extraction
│   │   │   └── test_file.rs     # Test file detection & analysis
│   │   └── queries/             # Tree-sitter S-expression queries
│   │       ├── typescript/      # routes, imports, api_calls, middleware, env_refs
│   │       ├── python/          # routes, env_refs
│   │       └── go/              # routes
│   ├── scanners/                # 28 scanners (S1–S28)
│   ├── reporters/               # Matrix table, gap report, task decomposer
│   └── dispatchers/             # stdout, Notion API, GitHub API
├── templates/                   # Starter config templates
└── tests/
    ├── fixtures/                # Test fixture files for all languages
    └── integration/             # End-to-end integration tests
```

### Data Flow

```
.sentinella.yaml
       │
       ▼
   ┌────────┐    parallel     ┌──────────────┐
   │ Config │───────────────▶│   Indexer     │
   └────────┘                │  (tree-sitter │
                             │   + regex)    │
                             └──────┬───────┘
                                    │
                              IndexStore
                           (DashMap, lock-free)
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │     5-Layer Scanner Engine          │
                    │  L1: S1+S6+S17+S20+S25 (parallel)  │
                    │  L2: S2+S9             (parallel)  │
                    │  L3: S3+S4+S7+S8+S12+S13+S14+S16  │
                    │      +S18+S19+S21+S22+S26+S27      │
                    │  L4: S10+S11+S15+S23+S24+S28       │
                    │                        (parallel)  │
                    │  L5: S5                (sequential)│
                    └───────────────┬───────────────┘
                                    │
                              ScanResult[]
                                    │
                     ┌──────────────┼──────────────┐
                     ▼              ▼              ▼
               ┌──────────┐  ┌──────────┐  ┌────────────┐
               │  Matrix  │  │   Gap    │  │   Task     │
               │ Reporter │  │ Reporter │  │ Decomposer │
               └──────────┘  └──────────┘  └─────┬──────┘
                                                  │
                                     ┌────────────┼────────────┐
                                     ▼            ▼            ▼
                                  stdout       Notion       GitHub
```

## Supported Languages

| Language | Route Parsing | Env Refs | Event Detection | Stub Detection |
|----------|:------------:|:--------:|:---------------:|:--------------:|
| TypeScript | tree-sitter | tree-sitter | regex | regex |
| Python | tree-sitter | tree-sitter | regex | regex |
| Go | tree-sitter | regex | regex | regex |
| SQL | regex (DDL) | — | — | — |
| Dockerfile | regex | — | — | — |
| YAML | regex | env extraction | — | — |
| .env | regex | env definitions | — | — |

## Output Examples

### Terminal Matrix

```
sentinella  system completeness audit

┌──────────┬─────────┬──────┬───────┬───────┐
│ Module   │ Backend │ BFF  │ Hooks │ Pages │
├──────────┼─────────┼──────┼───────┼───────┤
│ auth     │   ✅    │  ✅  │  ✅   │  ✅   │
│ dashboard│   ✅    │  ✅  │  ⚠️   │  ❌   │
│ billing  │   ✅    │  ❌  │  ❌   │  ❌   │
└──────────┴─────────┴──────┴───────┴───────┘

┌─────┬──────────────────────┬───────┬──────────┐
│ ID  │ Scanner              │ Score │ Severity │
├─────┼──────────────────────┼───────┼──────────┤
│ S1  │ Stub Detector        │  85   │ warning  │
│ S6  │ Residue Finder       │  70   │ warning  │
│ ...                                           │
└─────┴──────────────────────┴───────┴──────────┘
```

### Gap Report (excerpt)

```
[S1-StubDetector] score: 85/100
  ⚠ src/pages/dashboard.tsx:12 — uses hardcoded data (no fetch/useQuery detected)
  ⚠ src/hooks/useBilling.ts:5 — TODO: connect to real API

[S11-EnvConfigDrift] score: 60/100
  ⚠ DATABASE_URL — referenced in code but missing from docker-compose.yml
  ⚠ REDIS_HOST — referenced in code but missing from .env.example
```

## CI Integration

### GitHub Actions

Add a Sentinella audit step to any workflow:

```yaml
- name: Sentinella Audit
  run: |
    cargo install sentinella
    sentinella --config .sentinella.yaml
```

A full CI workflow is provided at `.github/workflows/ci.yml` — it runs formatting checks, Clippy lints, tests, release builds, and a security audit.

### Makefile Integration

Copy `templates/Makefile.sentinella` to your project and use the following targets:

```bash
make audit-code    # Terminal output
make audit-json    # JSON export
make audit-full    # Full pipeline (JSON export + terminal summary)
make audit-check   # CI quality gate (fails if score < 60)
```

Override the minimum score threshold:

```bash
make audit-check SENTINELLA_MIN_SCORE=80
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust (edition 2021) |
| CLI | clap 4 |
| AST Parsing | tree-sitter 0.24 (TypeScript, Python, Go) |
| Concurrency | Rayon (data parallelism) + DashMap (lock-free maps) |
| File Walking | ignore (ripgrep's walker, respects .gitignore) |
| Error Handling | miette (diagnostics) + anyhow + thiserror |
| HTTP Client | ureq 3 (Notion/GitHub API) |
| Terminal Output | comfy-table + owo-colors |
| Snapshot Testing | insta |

## License

MIT

---

<a id="中文文档"></a>

# Sentinella 中文文档

**系统完整性审计工具** — 检测残留桩代码、跨层断裂、API 契约漂移，并自动生成任务拆解。

## 什么是 Sentinella?

Sentinella 是一个静态分析工具，扫描你的整个项目 — 后端、BFF、Hooks、页面、数据库、部署配置 — 并报告**哪些东西缺失、哪些连接断裂、哪些配置漂移**。它不仅仅是代码检查工具：它理解你的系统架构，验证每一层是否正确连通。

### 核心能力

- **28 个专业扫描器**，覆盖桩代码、安全性、部署就绪、API 契约、事件、环境变量、数据隔离、认证安全、文档事实漂移等
- **Tree-sitter AST 解析**，支持 TypeScript、Python、Go — 精确语法分析，非正则猜测
- **跨层追踪**，从数据库到 API 到前端页面
- **5 层并行执行引擎**，基于 Rayon 实现最大性能
- **证据驱动 Check 管道** — scan → suppress → memory → calibrate → correlate → filter → render → state sync
- **规则包与生命周期** — 可安装的 YAML 规则包，支持 experimental/deprecated 生命周期过滤
- **任务派发**至 Notion 或 GitHub Issues，生成可执行的修复任务
- **单文件二进制，零运行时依赖** — 发布构建 `< 15MB`

## 安装

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/NiuChou/sentinella.git
cd sentinella

# 编译 release 版本
cargo build --release

# 二进制文件位于 target/release/sentinella
# 可选：全局安装
cargo install --path .
```

### 系统要求

- Rust 1.75+（edition 2021）
- 无外部运行时依赖

## 快速开始

```bash
# 1. 生成配置文件
sentinella init --type fullstack

# 2. 编辑 .sentinella.yaml，匹配你的项目结构
# 3. 运行审计
sentinella check

# 4. 仅运行指定扫描器
sentinella check --scanner S1,S6

# 5. 设置 CI 最低分数线（低于 80 则退出码非零）
sentinella check --min_coverage 80

# 6. 导出为 JSON 格式
sentinella check --format json

# 7. 生成任务拆解
sentinella dispatch
```

## CLI 命令参考

```
sentinella [--config <路径>] <命令>
```

### 全局参数

| 参数 | 说明 |
|------|------|
| `--config <路径>` | 指定配置文件路径，覆盖自动查找 |

### 命令

#### `sentinella check` — 运行完整性扫描

| 参数 | 短写 | 默认值 | 说明 |
|------|------|--------|------|
| `--dir <路径>` | `-d` | `.` | 项目根目录 |
| `--scanner <IDs>` | `-s` | 全部 | 过滤扫描器（如 `S1,S9`） |
| `--format <格式>` | `-f` | `terminal` | 输出格式：`terminal`、`json`、`markdown`、`notion` |
| `--min_coverage <N>` | | | 低于 N 分则以非零退出码退出 |

#### `sentinella init` — 生成配置文件

| 参数 | 短写 | 默认值 | 说明 |
|------|------|--------|------|
| `--type <类型>` | `-t` | `fullstack` | 模板：`fullstack`、`backend-only`、`monorepo` |

#### `sentinella dispatch` — 任务拆解与派发

| 参数 | 短写 | 默认值 | 说明 |
|------|------|--------|------|
| `--dir <路径>` | `-d` | `.` | 项目根目录 |
| `--target <目标>` | `-t` | `stdout` | 目标：`stdout`、`notion`、`github` |
| `--dry-run` | | `false` | 仅预览，不实际发送 |

#### `sentinella pack` — 规则包管理

| 子命令 | 说明 |
|--------|------|
| `pack list` | 列出所有可用规则包（内置 + 社区） |
| `pack validate <路径>` | 验证规则包 YAML 文件 |
| `pack install <路径>` | 安装社区规则包 |

内置规则包：`echo`、`chi`、`actix`、`axum`、`django`、`flask`、`spring-boot`、`rails`、`laravel`

## 扫描器详解

Sentinella 包含 28 个扫描器，分为 5 个执行层：

### 第 1 层 — 基础检测

| ID | 扫描器 | 检测内容 |
|----|--------|---------|
| **S1** | 桩代码检测器 | 前端页面/Hooks 使用硬编码数据而非真实 API 连接 |
| **S6** | 残留物查找器 | 全代码库的 TODO、FIXME、HACK、mock 数据、占位符 |
| **S17** | 静默错误吞没 | 空 catch 块、忽略的 Promise 拒绝、被吞没的异常 |
| **S20** | 敏感数据日志泄露 | 密码、Token、密钥、OTP 验证码出现在 log/console 调用中 |
| **S25** | 测试旁路检测 | 硬编码测试账号、万能密码、debug 标志绕过认证流程 |

### 第 2 层 — 核心追踪

| ID | 扫描器 | 检测内容 |
|----|--------|---------|
| **S2** | 跨层追踪器 | 后端 → BFF → Hooks → 页面链中缺失的连接 |
| **S9** | API 契约漂移 | 前端 API 调用与后端路由定义不匹配 |

### 第 3 层 — 完整性

| ID | 扫描器 | 检测内容 |
|----|--------|---------|
| **S3** | 流程分析器 | API 端点存在但页面未导入的断裂业务流程 |
| **S4** | 部署就绪检查 | Dockerfile 缺少健康检查、基础镜像未固定版本、以 root 运行 |
| **S7** | 安全完整性 | API 端点缺少鉴权中间件（auth、guard、jwt、session） |
| **S8** | 集成测试覆盖 | 数据库表缺少读/写/断言的集成测试 |
| **S12** | 数据隔离审计 | 幽灵表、未激活 RLS 策略、缺少租户过滤、仅缓存持久化、硬编码凭证 |
| **S13** | 破坏性端点安全 | DELETE/危险端点缺少二次确认、软删除或审计追踪 |
| **S14** | 软删除生命周期 | 缺少软删除过滤查询、无重新激活路径、PII 未清理 |
| **S16** | 角色硬编码 | 角色字符串硬编码而非使用集中式角色常量或枚举 |
| **S18** | Token 失效检查 | 状态变更操作（登出、停用、删除）未失效 Token/Session |
| **S19** | OTP 重放防护 | OTP 验证端点缺少重放保护或速率限制 |
| **S21** | 不安全 Token 存储 | 认证 Token 存储在 localStorage/sessionStorage 而非 httpOnly Cookie |
| **S22** | 限流覆盖率 | 认证端点缺少限流保护（暴力破解风险） |
| **S26** | Refresh Token 轮换 | 刷新令牌端点签发新 Token 但未吊销旧 Token |
| **S27** | 竞态条件安全 | 认证路径数据库写入（INSERT/UPSERT）缺少并发保护 |

### 第 4 层 — 漂移检测

| ID | 扫描器 | 检测内容 |
|----|--------|---------|
| **S10** | 事件模式漂移 | 事件主题被生产但从未被消费（或反之） |
| **S11** | 环境变量漂移 | 代码中引用的环境变量在部署配置中缺失 |
| **S15** | 跨服务重复 | Monorepo 项目中跨服务的重复业务逻辑 |
| **S23** | 审计日志完整性 | 状态变更操作（登录、DELETE、PUT、PATCH）缺少审计日志调用 |
| **S24** | 缺失唯一约束 | SQL WHERE 等值查找列缺少 UNIQUE 约束 |
| **S28** | 文档事实漂移 | README/文档中的声明与实际代码不一致（端口、依赖、版本、镜像、环境变量） |

### 第 5 层 — 项目

| ID | 扫描器 | 检测内容 |
|----|--------|---------|
| **S5** | 计划漂移 | Notion 项目计划与实际代码库之间的偏差 |

> 各层按顺序执行；同一层内的扫描器通过 Rayon **并行运行**。

### S12 数据隔离审计 — 检测规则

S12 实现 **10 条检测规则**，覆盖 3 个维度，验证数据层隔离完整性：

#### 维度 A：模式-代码对齐

| 规则 | ID | 严重性 | 检测内容 |
|------|----|--------|---------|
| 幽灵表 | D1 | 严重 | 迁移脚本定义了 `CREATE TABLE` 但应用代码从未写入该表 |
| RLS 未激活 | D2 | 严重 | RLS 策略使用 `current_setting('app.XXX')` 但应用代码从未调用 `SET LOCAL` |
| ENABLE 未 FORCE | D3 | 警告 | 存在 `ENABLE ROW LEVEL SECURITY` 但缺少 `FORCE ROW LEVEL SECURITY` — 表所有者绕过 RLS |

#### 维度 B：查询隔离

| 规则 | ID | 严重性 | 检测内容 |
|------|----|--------|---------|
| 缺少所有权过滤 | D4 | 警告 | 写端点（POST/PUT/DELETE）查询用户作用域表但缺少租户列过滤条件 |
| IDOR 风险 GET | D5 | 信息 | GET 端点按 ID 返回记录但在 RLS 保护表上缺少租户过滤 |

#### 维度 C：基础设施隔离

| 规则 | ID | 严重性 | 检测内容 |
|------|----|--------|---------|
| 仅缓存持久化 | D6 | 警告 | 数据写入 Redis 并设置 TTL，但同一上下文中无对应的数据库写入 |
| 硬编码凭证 | D7 | 严重 | 硬编码的凭证值（`password`、`secret`、`key`、`token`）应使用环境变量 |
| 双池检测 | D8 | 警告 | 双池检测 — 用户端代码使用 admin 数据库连接池而非受限 RLS 连接池 |
| Redis Key 枚举风险 | D9 | 警告 | Redis Key 枚举风险 — 基于 session 的 key 缺少 user_id 前缀 |
| 跨服务数据泄漏 | D10 | 警告 | 跨服务数据泄漏 — monorepo 中服务直接查询其他服务的表 |

> 完整实施计划和评分模型请参考 `docs/S12-data-isolation-audit-plan.md`。

## 配置指南

Sentinella 在项目根目录（或上级目录）查找 `.sentinella.yaml`。使用 `--config` 指定自定义路径。

### 最简配置

```yaml
version: "1.0"
project: my-app
type: fullstack

layers:
  backend:
    pattern: "src/server/**/*.ts"

output:
  format: terminal
  min_coverage: 80
  severity: warning
```

### 完整配置项

| 配置块 | 用途 | 关联扫描器 |
|--------|------|-----------|
| `layers` | 定义逻辑层与文件 glob 映射 | S1, S2, S6, S7 |
| `modules` | 跨层模块映射（backend/bff/hooks/page） | S2 |
| `flows` | 关键业务流程步骤定义 | S3 |
| `deploy` | Dockerfile 检查规则 | S4 |
| `integration_tests` | 集成测试路径与规则 | S8 |
| `events` | 事件生产者/消费者文件模式 | S10 |
| `env` | 环境变量代码/部署模式匹配 | S11 |
| `data_isolation` | 数据隔离检查：租户列、RLS 会话变量、排除表、凭证关键词 | S12 |
| `output` | 输出格式与最低覆盖率 | 全部 |
| `dispatch` | 任务派发目标配置 | — |

> S13-S28 为零配置扫描器，基于代码索引自动检测，无需额外配置项。

> 完整配置示例请参考 `templates/fullstack.yaml`

## 架构概览

```
.sentinella.yaml
       │
       ▼
   ┌────────┐    并行解析    ┌──────────────┐
   │  配置  │──────────────▶│   索引器      │
   └────────┘               │ (tree-sitter  │
                            │  + 正则)      │
                            └──────┬───────┘
                                   │
                             IndexStore
                          (DashMap, 无锁并发)
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │     5 层扫描执行引擎                │
                   │  L1: S1+S6+S17+S20+S25 (并行)  │
                   │  L2: S2+S9             (并行)  │
                   │  L3: S3+S4+S7+S8+S12+S13+S14  │
                   │      +S16+S18+S19+S21+S22      │
                   │      +S26+S27          (并行)  │
                   │  L4: S10+S11+S15+S23+S24+S28   │
                   │                        (并行)  │
                   │  L5: S5               (串行)   │
                   └───────────────┬───────────────┘
                                   │
                             ScanResult[]
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              ┌──────────┐  ┌──────────┐  ┌────────────┐
              │  矩阵    │  │  缺口    │  │   任务     │
              │  报告器  │  │  报告器  │  │  拆解器    │
              └──────────┘  └──────────┘  └─────┬──────┘
                                                │
                                   ┌────────────┼────────────┐
                                   ▼            ▼            ▼
                                stdout       Notion       GitHub
```

## 支持的语言

| 语言 | 路由解析 | 环境变量 | 事件检测 | 桩代码检测 |
|------|:--------:|:--------:|:--------:|:----------:|
| TypeScript | tree-sitter | tree-sitter | 正则 | 正则 |
| Python | tree-sitter | tree-sitter | 正则 | 正则 |
| Go | tree-sitter | 正则 | 正则 | 正则 |
| SQL | 正则 (DDL) | — | — | — |
| Dockerfile | 正则 | — | — | — |
| YAML | 正则 | 环境变量提取 | — | — |
| .env | 正则 | 环境变量定义 | — | — |

## CI 集成

### GitHub Actions

在任意工作流中添加 Sentinella 审计步骤：

```yaml
- name: Sentinella Audit
  run: |
    cargo install sentinella
    sentinella --config .sentinella.yaml
```

完整的 CI 工作流位于 `.github/workflows/ci.yml` -- 包含格式检查、Clippy 静态分析、测试、Release 构建和安全审计。

### Makefile 集成

将 `templates/Makefile.sentinella` 复制到你的项目中，使用以下目标：

```bash
make audit-code    # 终端输出
make audit-json    # JSON 导出
make audit-full    # 完整流程（JSON 导出 + 终端摘要）
make audit-check   # CI 质量门禁（分数低于 60 则失败）
```

覆盖最低分数阈值：

```bash
make audit-check SENTINELLA_MIN_SCORE=80
```

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Rust（edition 2021） |
| CLI 框架 | clap 4 |
| AST 解析 | tree-sitter 0.24（TypeScript、Python、Go） |
| 并发 | Rayon（数据并行）+ DashMap（无锁哈希表） |
| 文件遍历 | ignore（ripgrep 的 walker，自动尊重 .gitignore） |
| 错误处理 | miette（诊断信息）+ anyhow + thiserror |
| HTTP 客户端 | ureq 3（Notion/GitHub API） |
| 终端输出 | comfy-table + owo-colors |
| 快照测试 | insta |

## 开源协议

MIT
