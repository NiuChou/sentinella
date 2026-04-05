# S12 Data Isolation Audit — Implementation Plan

# S12 数据隔离审计 — 实施计划

---

## 1. Background / 背景

### 1.1 Why this scanner? / 为什么需要这个扫描器？

Two real-world audit reports revealed a pattern that existing Sentinella scanners cannot detect:

两份实际项目审查报告揭示了现有 Sentinella 扫描器无法检测的漏洞模式：

| Source | Key Finding |
|--------|-------------|
| [Data Isolation Audit v3.3](https://www.notion.so/33985219e4b3815db168e74328dbfc9c) (lumi-ai) | `factor_results` table created in migration but **never written to** by app code; RLS policies configured but `SET LOCAL` **never called**; Redis used as sole source of truth without DB persistence |
| [Data Isolation Long-Term Fix Plan](https://www.notion.so/33985219e4b381ab9156ee986ed197af) (perseworks) | 20+ tables with `ENABLE RLS` but no `FORCE RLS`; repository layer using raw pool instead of RLS-aware dual pool; 5 IDOR endpoints missing ownership verification; default credentials hardcoded |

**Common root cause**: DB schema and application code are written at different velocities. Migration scripts add tables and RLS policies, but application code either never catches up, or connects with a superuser role that bypasses all protections.

**共同根因**：DB schema 和应用代码以不同节奏迭代。迁移脚本添加了表和 RLS 策略，但应用代码要么从未跟上，要么用超级角色连接绕过了所有保护。

### 1.2 What existing scanners already cover / 现有扫描器已覆盖内容

| Scanner | Existing Coverage | Gap |
|---------|-------------------|-----|
| S7 SecurityCompleteness | Auth middleware on endpoints; multi-tenancy hints on tables | No schema-code alignment; no RLS activation check |
| S8 IntegrationTestCov | RLS alignment in tests; table test coverage | Detection only, not isolation verification |
| S11 EnvConfigDrift | Env var drift code↔deploy | No `DATABASE_URL_APP` dual-role pattern |

**Conclusion**: S12 fills a distinct gap — **data layer isolation verification** — that S7/S8/S11 touch tangentially but never address directly.

**结论**：S12 填补了一个独特空白 — **数据层隔离验证** — S7/S8/S11 只是侧面触及但从未直接解决。

---

## 2. Detection Rules / 检测规则

Based on both audit reports, we define **7 detection rules** across 3 dimensions:

基于两份审查报告，我们定义 **7 条检测规则**，覆盖 3 个维度：

### Dimension A: Schema-Code Alignment / 模式-代码对齐

| Rule | ID | Severity | Detection Logic | Real-World Example |
|------|----|----------|-----------------|-------------------|
| Ghost Table | D1 | **Critical** | Migration defines `CREATE TABLE X` but no `INSERT INTO X` / `UPDATE X` / ORM write to `X` found in application code | lumi-ai `factor_results` — table exists since `001_initial.sql` but `_save_factor_result()` only writes to Redis |
| RLS Not Activated | D2 | **Critical** | Table has `CREATE POLICY ... USING(user_id = current_setting('app.XXX'))` but application code has zero matches for `SET LOCAL app.XXX` / `set_config('app.XXX')` | lumi-ai — `002_rls.sql` configures 9 tables but Python code never calls `SET LOCAL` |
| ENABLE Without FORCE | D3 | **Warning** | `ALTER TABLE X ENABLE ROW LEVEL SECURITY` found but no `ALTER TABLE X FORCE ROW LEVEL SECURITY` — table owner role silently bypasses RLS | perseworks PLM — 7 tables had ENABLE but not FORCE; owner role queries returned all rows |

### Dimension B: Query Isolation / 查询隔离

| Rule | ID | Severity | Detection Logic | Real-World Example |
|------|----|----------|-----------------|-------------------|
| Missing Ownership Filter | D4 | **Warning** | Write endpoint (POST/PUT/DELETE) executes SQL on a user-scoped table but the query has no `WHERE user_id` / `WHERE owner_id` / equivalent tenant column | perseworks Altus — `AppendMessage` writes to `conversations` without ownership check |
| IDOR-Prone GET | D5 | **Info** | GET endpoint returns records by ID without joining/filtering on tenant column, on a table that has RLS or `app_role` | perseworks Altus — `GetPromptTemplate` returns private templates to any user |

### Dimension C: Infrastructure Isolation / 基础设施隔离

| Rule | ID | Severity | Detection Logic | Real-World Example |
|------|----|----------|-----------------|-------------------|
| Cache-Only Persistence | D6 | **Warning** | Data written to Redis key pattern (SET/HSET/ZADD) with a TTL, but no corresponding DB table write in the same function/handler | lumi-ai — DRP balance stored only in Redis `drp:balance:{user_id}`, `drp_accounts` table unused |
| Default Credential | D7 | **Critical** | Config/code contains hardcoded credential patterns: `password = "..."`, `secret = "..."`, `key = "..."` with non-empty string literal (not env var reference) | perseworks — MinIO `minioadmin`, federation `federation_secret`, internal API `dev-internal-key` |

> **Note on D7**: This overlaps slightly with S11 (EnvConfigDrift) which checks env vars exist in deploy configs. D7 is different — it detects **hardcoded default values** that should not exist at all, not missing env var declarations.

> **关于 D7 的说明**：这与 S11（EnvConfigDrift）有轻微重叠，S11 检查环境变量是否存在于部署配置中。D7 不同 — 它检测的是**不应存在的硬编码默认值**，而非缺失的环境变量声明。

---

## 3. Architecture / 架构设计

### 3.1 Execution Layer Placement / 执行层归属

```
Layer 3 (Completeness): S3 + S4 + S7 + S8 + S12   ← S12 joins this layer
```

S12 runs in parallel with S3/S4/S7/S8 because:
- It depends on IndexStore data (populated in indexing phase) — no scanner dependency
- Its detection rules (schema-code alignment, query isolation) are completeness checks
- D2/D3 (RLS checks) complement S7 (auth middleware) and S8 (RLS test alignment)

S12 与 S3/S4/S7/S8 并行执行，因为：
- 它依赖 IndexStore 数据（在索引阶段填充）— 无扫描器依赖
- 其检测规则（模式-代码对齐、查询隔离）属于完整性检查
- D2/D3（RLS 检查）与 S7（鉴权中间件）和 S8（RLS 测试对齐）互补

### 3.2 Index Extensions / 索引扩展

**New types in `types.rs`:**

```rust
/// A reference to a database write operation found in application code.
#[derive(Debug, Clone)]
pub struct DbWriteRef {
    pub table_name: String,
    pub operation: DbWriteOp,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbWriteOp {
    Insert,
    Update,
    Upsert,
    Delete,
}

/// A Redis key pattern found in application code.
#[derive(Debug, Clone)]
pub struct RedisKeyRef {
    pub key_pattern: String,       // e.g., "drp:balance:{user_id}"
    pub operation: RedisOp,
    pub has_ttl: bool,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisOp {
    Read,   // GET, HGET, SMEMBERS, etc.
    Write,  // SET, HSET, ZADD, etc.
    Delete, // DEL, HDEL, etc.
}

/// An RLS session variable setting found in application code.
#[derive(Debug, Clone)]
pub struct RlsContextRef {
    pub session_var: String,       // e.g., "app.current_user_id"
    pub file: PathBuf,
    pub line: usize,
}

/// A hardcoded credential found in application code or config.
#[derive(Debug, Clone)]
pub struct HardcodedCredential {
    pub key_name: String,          // e.g., "minio_access_key"
    pub value_hint: String,        // first 4 chars + "***"
    pub file: PathBuf,
    pub line: usize,
}

/// RLS policy detail extracted from SQL migrations.
#[derive(Debug, Clone)]
pub struct RlsPolicyInfo {
    pub table_name: String,
    pub policy_name: String,
    pub session_var: Option<String>,  // extracted from current_setting('app.XXX')
    pub has_force: bool,              // FORCE ROW LEVEL SECURITY
    pub role: Option<String>,         // TO role_name
}

/// SQL query with table reference found in application code.
#[derive(Debug, Clone)]
pub struct SqlQueryRef {
    pub table_name: String,
    pub operation: SqlQueryOp,
    pub has_tenant_filter: bool,      // WHERE user_id / owner_id / tenant_id
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlQueryOp {
    Select,
    Insert,
    Update,
    Delete,
}
```

**New DashMaps in `store.rs`:**

```rust
pub struct IndexStore {
    // ... existing fields ...

    // S12: Data Isolation
    pub db_write_refs: DashMap<String, Vec<DbWriteRef>>,         // key = table_name
    pub redis_key_refs: DashMap<String, Vec<RedisKeyRef>>,       // key = key_pattern_prefix
    pub rls_context_refs: DashMap<PathBuf, Vec<RlsContextRef>>,  // key = file
    pub rls_policies: DashMap<String, Vec<RlsPolicyInfo>>,       // key = table_name
    pub hardcoded_creds: DashMap<PathBuf, Vec<HardcodedCredential>>, // key = file
    pub sql_query_refs: DashMap<String, Vec<SqlQueryRef>>,       // key = table_name
}
```

### 3.3 Parser Extensions / 解析器扩展

| Parser | New Extraction | Method |
|--------|---------------|--------|
| `sql.rs` | `RlsPolicyInfo` (session_var, has_force) | Regex: `current_setting\('([^']+)'` in POLICY body; `FORCE ROW LEVEL SECURITY` |
| `typescript.rs` | `DbWriteRef` (INSERT/UPDATE in template literals), `RedisKeyRef`, `RlsContextRef` | Regex on raw SQL strings + Redis client patterns |
| `python.rs` | `DbWriteRef` (SQLAlchemy `text("INSERT...")`), `RedisKeyRef`, `RlsContextRef` (`SET LOCAL`) | Regex: `text\("(INSERT\|UPDATE)`, `redis.*\.(set\|hset)`, `SET LOCAL` |
| `go_lang.rs` | `DbWriteRef` (pgx `Exec`/`Query` with INSERT), `RedisKeyRef`, `RlsContextRef` | Regex: `\.Exec\(.*INSERT`, `\.Set\(ctx,`, `SET LOCAL` |
| All parsers | `HardcodedCredential` | Regex: `(password\|secret\|key\|token)\s*[:=]\s*"[^"]{4,}"` (exclude env var refs) |

### 3.4 Configuration Schema / 配置 Schema

```rust
// schema.rs — new block
#[derive(Debug, Clone, Deserialize)]
pub struct DataIsolationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Column name used for tenant/user isolation (default: "user_id")
    #[serde(default = "default_tenant_column")]
    pub tenant_column: String,

    /// Additional column names that qualify as tenant isolation
    #[serde(default)]
    pub tenant_column_aliases: Vec<String>,

    /// Expected RLS session variable (default: "app.current_user_id")
    #[serde(default = "default_rls_session_var")]
    pub rls_session_var: String,

    /// Tables to exclude from isolation checks
    #[serde(default)]
    pub exclude_tables: Vec<String>,

    /// Redis key patterns expected to NOT have user scope
    #[serde(default)]
    pub exclude_redis_patterns: Vec<String>,

    /// Roles that are allowed to bypass RLS (for workers/admin)
    #[serde(default)]
    pub admin_roles: Vec<String>,

    /// Credential key names to scan for hardcoded values
    #[serde(default = "default_credential_keys")]
    pub credential_keys: Vec<String>,
}
```

**YAML example:**

```yaml
data_isolation:
  enabled: true
  tenant_column: "user_id"
  tenant_column_aliases:
    - "owner_id"
    - "project_id"          # perseworks: RequireProjectAccess pattern
  rls_session_var: "app.current_user_id"
  exclude_tables:
    - _prisma_migrations
    - schema_migrations
    - spatial_ref_sys
  exclude_redis_patterns:
    - "jwt:blacklist:*"     # token-scoped, not user-scoped
    - "sse_ticket:*"        # ephemeral by design
    - "ratelimit:*"         # IP-scoped is valid
  admin_roles:
    - lumi                  # lumi-ai superuser
    - plm_service           # perseworks worker role
    - bee_service
  credential_keys:
    - password
    - secret
    - api_key
    - access_key
    - token
```

---

## 4. Scanner Logic / 扫描器逻辑

### 4.1 Scoring Model / 评分模型

```
Total Score = weighted average of 3 dimension scores

Dimension A (Schema-Code): 40% weight
  - D1 Ghost Table:          -15 per table (Critical)
  - D2 RLS Not Activated:    -20 per table (Critical)
  - D3 ENABLE Without FORCE: -5 per table  (Warning)

Dimension B (Query Isolation): 35% weight
  - D4 Missing Ownership:    -10 per endpoint (Warning)
  - D5 IDOR-Prone GET:       -3 per endpoint  (Info)

Dimension C (Infrastructure): 25% weight
  - D6 Cache-Only:           -8 per pattern  (Warning)
  - D7 Default Credential:   -20 per finding (Critical)

Floor: 0, Ceiling: 100
```

### 4.2 Pseudocode / 伪代码

```
fn scan(ctx) -> ScanResult:
    findings = []

    // === Dimension A: Schema-Code Alignment ===

    // D1: Ghost Table
    for table in index.db_tables:
        if table NOT IN config.exclude_tables:
            write_refs = index.db_write_refs.get(table.name)
            if write_refs is empty:
                findings.push(Critical: "Table '{table}' defined in migration but never written to by application code")

    // D2: RLS Not Activated
    rls_tables = index.rls_policies where session_var is Some
    if rls_tables.any():
        rls_context_found = index.rls_context_refs.values().any(|refs|
            refs.iter().any(|r| r.session_var == config.rls_session_var))
        if NOT rls_context_found:
            for table in rls_tables:
                findings.push(Critical: "Table '{table}' has RLS policy using '{session_var}' but SET LOCAL never called")

    // D3: ENABLE Without FORCE
    for table in index.db_tables where has_rls == true:
        policy = index.rls_policies.get(table.name)
        if policy is None OR NOT policy.has_force:
            findings.push(Warning: "Table '{table}' has ENABLE RLS but not FORCE RLS — owner role bypasses")

    // === Dimension B: Query Isolation ===

    // D4: Missing Ownership Filter
    for endpoint in index.api_endpoints where method is POST|PUT|DELETE:
        queries_in_handler = index.sql_query_refs correlated by file proximity
        for query in queries_in_handler:
            if query.table is user-scoped (has_rls or app_role) AND NOT query.has_tenant_filter:
                findings.push(Warning: "Write endpoint {method} {path} queries '{table}' without tenant filter")

    // D5: IDOR-Prone GET
    for endpoint in index.api_endpoints where method is GET:
        queries_in_handler = index.sql_query_refs correlated by file
        for query in queries_in_handler:
            if query.table is user-scoped AND NOT query.has_tenant_filter AND query.op == Select:
                findings.push(Info: "GET {path} reads '{table}' by ID without tenant filter — potential IDOR")

    // === Dimension C: Infrastructure ===

    // D6: Cache-Only Persistence
    for (pattern, redis_refs) in index.redis_key_refs:
        if pattern NOT IN config.exclude_redis_patterns:
            writes = redis_refs.filter(|r| r.operation == Write && r.has_ttl)
            if writes.any():
                // Check if any DB write exists in the same file/function context
                same_context_db_writes = index.db_write_refs correlated by file
                if same_context_db_writes.is_empty():
                    findings.push(Warning: "Redis key '{pattern}' written with TTL but no DB persistence in same context")

    // D7: Default Credential
    for (file, creds) in index.hardcoded_creds:
        for cred in creds:
            findings.push(Critical: "Hardcoded credential '{key_name}' = '{hint}' — use env var or secret manager")

    score = compute_weighted_score(findings)
    return ScanResult { scanner: "S12", findings, score, summary }
```

---

## 5. Interaction with Existing Scanners / 与现有扫描器的交互

| Existing Scanner | Interaction | Enhancement |
|-----------------|-------------|-------------|
| **S7** SecurityCompleteness | S7 checks auth middleware; S12 checks data-layer isolation **below** the middleware | S7's `suggests_multi_tenancy()` can reuse S12's `tenant_column` config for accuracy |
| **S8** IntegrationTestCov | S8 verifies tests exercise RLS path; S12 verifies RLS is actually **activatable** | S12 D2 finding ("RLS never called") upgrades S8's RLS test finding from "test doesn't verify RLS" to "RLS is structurally dead" |
| **S11** EnvConfigDrift | S11 checks env vars exist in deploy; S12 D7 checks values aren't hardcoded | Complementary: S11 catches missing vars, S12 D7 catches unsafe default values |
| **S6** ResidueFinder | S6 detects TODO/FIXME/placeholder text; S12 D1 detects structural ghost tables | Different signal types: text residue vs structural residue |

### Upgrade Path for S7

Once S12 is implemented, S7's `check_db_tables_tenancy()` function becomes redundant — S12 D4/D5 provide a more precise version. We should:

1. Keep S7 focused on **auth middleware coverage** (its primary mission)
2. Deprecate `suggests_multi_tenancy()` from S7
3. Let S12 own all data-layer isolation checks

一旦 S12 实现，S7 的 `check_db_tables_tenancy()` 功能变得冗余。建议：
1. S7 聚焦于**鉴权中间件覆盖**（其核心职责）
2. 从 S7 中弃用 `suggests_multi_tenancy()`
3. 让 S12 接管所有数据层隔离检查

---

## 6. Implementation Plan / 实施计划

### Phase 1: Index Foundation (索引基础)

**Files**: `types.rs`, `store.rs`, `sql.rs`

| Task | Est. Lines | Description |
|------|-----------|-------------|
| Add 7 new types to `types.rs` | ~80 | `DbWriteRef`, `RedisKeyRef`, `RlsContextRef`, `HardcodedCredential`, `RlsPolicyInfo`, `SqlQueryRef` + enums |
| Add 6 new DashMaps to `store.rs` + helpers | ~60 | `db_write_refs`, `redis_key_refs`, `rls_context_refs`, `rls_policies`, `hardcoded_creds`, `sql_query_refs` |
| Extend `sql.rs` | ~80 | Extract `RlsPolicyInfo` (session_var via `current_setting` regex, `FORCE RLS` detection) |
| Add `DataIsolationConfig` to `schema.rs` | ~50 | New config block with defaults |
| SQL fixture + tests | ~60 | Extend `migrations.sql` with FORCE RLS, session_var in policy body |

**Subtotal**: ~330 lines

### Phase 2: Parser Extensions (解析器扩展)

**Files**: `typescript.rs`, `python.rs`, `go_lang.rs`

| Task | Est. Lines | Description |
|------|-----------|-------------|
| TypeScript: extract DB writes from template literals | ~40 | Regex: `` `INSERT INTO (\w+)` ``, Prisma `.create()` patterns |
| TypeScript: extract Redis key patterns | ~30 | Regex: `redis\.(set|get|hset)\(["']([^"']+)` |
| Python: extract DB writes from SQLAlchemy `text()` | ~40 | Regex: `text\(\s*"(INSERT|UPDATE|DELETE)\s+\w+\s+(\w+)` |
| Python: extract `SET LOCAL` / `set_config` calls | ~20 | Regex: `SET LOCAL\s+(\S+)`, `set_config\('([^']+)'` |
| Go: extract DB writes from pgx Exec/Query | ~40 | Regex: `\.Exec\(.*"(INSERT|UPDATE|DELETE)\s+INTO\s+(\w+)` |
| Go: extract Redis patterns (go-redis) | ~30 | Regex: `\.(Set|Get|HSet)\(ctx,\s*"([^"]+)` |
| All: hardcoded credential scan | ~50 | Shared regex: `(password|secret|key|token)\s*[:=]\s*"[^"]{4,}"` excluding env refs |
| Parser tests | ~80 | Unit tests for each new extraction |

**Subtotal**: ~330 lines

### Phase 3: Scanner Implementation (扫描器实现)

**Files**: `data_isolation.rs` (NEW), `scanners/mod.rs`

| Task | Est. Lines | Description |
|------|-----------|-------------|
| `data_isolation.rs` — D1 Ghost Table | ~40 | Cross-reference `db_tables` × `db_write_refs` |
| `data_isolation.rs` — D2 RLS Not Activated | ~35 | Cross-reference `rls_policies` × `rls_context_refs` |
| `data_isolation.rs` — D3 ENABLE Without FORCE | ~25 | Check `rls_policies.has_force` |
| `data_isolation.rs` — D4 Missing Ownership | ~45 | Cross-reference `api_endpoints` × `sql_query_refs` × `has_tenant_filter` |
| `data_isolation.rs` — D5 IDOR-Prone GET | ~30 | Similar to D4, GET-only, Info severity |
| `data_isolation.rs` — D6 Cache-Only | ~40 | Cross-reference `redis_key_refs(Write+TTL)` × `db_write_refs` by file |
| `data_isolation.rs` — D7 Default Credential | ~25 | Iterate `hardcoded_creds` |
| Scoring + summary | ~40 | 3-dimension weighted scoring |
| Register in `scanners/mod.rs` | ~5 | Add to Layer 3, update EXECUTION_LAYERS |
| Unit tests | ~150 | 7 rules × ~2 tests each + scoring + edge cases |

**Subtotal**: ~435 lines

### Phase 4: Integration & Polish (集成与打磨)

| Task | Est. Lines | Description |
|------|-----------|-------------|
| Refactor S7: remove `check_db_tables_tenancy()` | -30 | S12 D4/D5 replaces this |
| Update `task_decomposer.rs` | ~20 | Map S12 findings → task types (FixRLS, FixGhostTable, FixCredential) |
| Update `README.md` | ~40 | Add S12 documentation in both languages |
| Integration test fixture | ~30 | Mixed SQL+Python+TS fixture exercising S12 |
| Fullstack template update | ~15 | Add `data_isolation:` block to `templates/fullstack.yaml` |

**Subtotal**: ~75 lines (net)

---

## 7. Total Estimate / 总估算

| Phase | Lines | Parallelizable |
|-------|-------|---------------|
| Phase 1: Index Foundation | ~330 | Agent A |
| Phase 2: Parser Extensions | ~330 | Agent B (after Phase 1 types) |
| Phase 3: Scanner Implementation | ~435 | Agent C (after Phase 1+2) |
| Phase 4: Integration | ~75 | Agent D (after Phase 3) |
| **Total** | **~1,170** | **3 waves** |

**Execution strategy / 执行策略:**

```
Wave 1 (parallel):
  Agent A: types.rs + store.rs + schema.rs + sql.rs extension
  Agent B: Fixture files for testing

Wave 2 (parallel, after Wave 1):
  Agent C: typescript.rs parser extensions
  Agent D: python.rs parser extensions
  Agent E: go_lang.rs parser extensions
  Agent F: Hardcoded credential scanner (all parsers)

Wave 3 (parallel, after Wave 2):
  Agent G: data_isolation.rs (D1-D7 + scoring)
  Agent H: S7 refactor + mod.rs + task_decomposer update
  Agent I: Tests + fixtures + README + template updates
```

---

## 8. Verification Criteria / 验证标准

### Must-pass scenarios (from real audit reports):

| # | Scenario | Expected Finding | Source |
|---|----------|-----------------|--------|
| 1 | SQL has `CREATE TABLE factor_results` + `CREATE POLICY`, but Python code has no `INSERT INTO factor_results` | D1 Critical: Ghost Table | lumi-ai |
| 2 | SQL has `ENABLE RLS` on 9 tables + `current_setting('app.current_user_id')`, Python code has zero `SET LOCAL` | D2 Critical: RLS Not Activated | lumi-ai |
| 3 | SQL has `ENABLE RLS` but no `FORCE RLS` on 7 tables | D3 Warning: ENABLE Without FORCE | perseworks PLM |
| 4 | POST `/messages` handler runs `INSERT INTO conversations` without `WHERE user_id` | D4 Warning: Missing Ownership | perseworks Altus |
| 5 | GET `/templates/:id` returns row by ID, no `user_id` filter, table has RLS | D5 Info: IDOR-Prone GET | perseworks Altus |
| 6 | Python code: `redis.set("drp:balance:{user_id}", value, ex=86400)`, no `INSERT INTO drp_accounts` nearby | D6 Warning: Cache-Only | lumi-ai |
| 7 | Go config: `MinioAccessKey: "minioadmin"` | D7 Critical: Default Credential | perseworks |

### Regression safety:

- All existing 176 tests must continue to pass
- S7 score should remain stable (multi-tenancy check moves to S12 but equivalent findings still generated)
- Integration tests must include at least one S12 finding

---

## 9. Future Extensions / 未来扩展

Not in scope for v1, but designed for:

| Extension | Description | Trigger |
|-----------|-------------|---------|
| **D8 Dual-Pool Detection** | Verify that user-facing services use restricted DB role, workers use admin role (perseworks `rlspool` pattern) | When `admin_roles` is configured |
| **D9 Redis Key Enumeration Risk** | Flag Redis keys using `session_id` without `user_id` prefix (lumi-ai session:state pattern) | When `exclude_redis_patterns` is configured |
| **D10 Cross-Service Data Leak** | In monorepo, verify Service A cannot query Service B's tables directly | When `type: monorepo` is configured |
| **tree-sitter SQL query** | Replace regex-based SQL extraction with tree-sitter-sql for higher precision | When tree-sitter-sql stabilizes |

---

*Plan authored: 2026-04-05*
*Based on: Data Isolation Audit v3.3 (lumi-ai) + Data Isolation Long-Term Fix Plan (perseworks)*
