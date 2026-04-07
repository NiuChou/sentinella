# Sentinella 误报分析与泛化架构优化计划

## 一、三次审计数据汇总

| 审计 | 目标项目 | 技术栈 | 总 Findings | 真实问题 | 误报率 |
|------|----------|--------|------------|---------|--------|
| v0.1.0 (LUMI) | Python + Rust 全栈 | FastAPI / Axum | 572 | ~60 | ~80% |
| v3.3.0 (大型) | 微服务架构 | NestJS / Next.js / Go | 6,080 | ~790 | ~87% |
| v3.3.0 (Konda) | 全栈单体 | NestJS / Next.js | ~885 | ~14 | ~98% |

**核心结论：当前整体误报率 80-98%，且每换一种技术栈，误报模式完全不同。**

---

## 二、根本问题：不是 Bug，是架构缺陷

### 当前架构的三层硬编码

经过源码审计，发现 Sentinella 存在 **三层硬编码**，导致工具既不准确又无法泛化：

```
┌─────────────────────────────────────────────┐
│  Layer 3: Scanner 层 — 硬编码判定规则        │
│  AUTH_KEYWORDS = ["auth","guard","verify"..] │
│  "所有 DELETE 必须 2FA"                       │
│  "任何 UPDATE 必须 token 失效"                │
├─────────────────────────────────────────────┤
│  Layer 2: Parser 层 — 硬编码框架知识         │
│  NestJS @Controller / @Get / @UseGuards      │
│  Express router.get/post/use                 │
│  FastAPI @app.get — 但不提取 Depends()       │
│  Gin r.GET — 但不提取 .Use()                 │
│  Go/Python/Rust 完全没有 middleware 提取      │
├─────────────────────────────────────────────┤
│  Layer 1: 索引层 — 硬编码模式和关键字        │
│  real_data_indicators: fetch/axios/useQuery   │
│  stub_indicators: TODO/FIXME/PLACEHOLDER      │
│  credential_keys: password/secret/token       │
│  EXCLUDED_VAR_PREFIXES: GITHUB_/VERCEL_      │
│  sensitive_log: password|token|secret|otp     │
└─────────────────────────────────────────────┘
```

**后果**：

| 问题 | 表现 | 影响 |
|------|------|------|
| 框架绑定 | 只完整支持 Express + 部分 NestJS；FastAPI/Gin/Django/Spring 大量漏检或误报 | 切换技术栈就失效 |
| 规则不可调 | "DELETE 必须 2FA" 写死在 Rust 代码里，用户无法覆盖 | 不同业务场景无法适配 |
| 无抑制出口 | 无 inline ignore、无 dismiss、无 confidence 分级 | 误报永远存在 |
| 新增成本高 | 支持一个新框架 = 修改 parser + 修改 scanner + 重编译 | 无法社区贡献 |

---

## 三、泛化设计目标

### 设计原则

1. **Rust 核心 = 框架无关引擎** — 核心只做 AST 遍历、正则匹配、跨文件追踪，不包含任何框架知识
2. **框架知识 = 外部规则文件** — YAML/TOML 声明式规则包，可分发、可社区贡献、无需重编译
3. **用户配置 > 内置规则 > 硬编码默认** — 三级覆盖，用户始终有最终决定权
4. **无罪推定** — parser 无法确认时标记为 `Suspect`，而非 `Critical`
5. **证据双向收集** — 同时收集"可能有问题"和"已被保护"的证据

### 目标用户矩阵

| 用户类型 | 场景 | 需要的能力 |
|----------|------|-----------|
| 开箱即用 | `sentinella check` 直接跑 | 内置规则包自动匹配技术栈 |
| 配置调优 | 项目有特殊模式 | `.sentinella.yaml` 覆盖规则 |
| 规则扩展 | 使用冷门框架 / 自定义框架 | 自定义规则包 YAML |
| 社区贡献 | 为新框架写规则 | 提交 `.sentinella/rules/xxx.yaml` PR |

---

## 四、泛化架构设计

### 4.1 规则包系统 (Rule Pack)

**核心思想：将所有框架知识从 Rust 代码迁移到声明式 YAML 规则包。**

#### 目录结构

```
~/.sentinella/rules/              # 全局规则包
  builtin/
    express.yaml
    nestjs.yaml
    fastapi.yaml
    django.yaml
    flask.yaml
    gin.yaml
    echo.yaml
    chi.yaml
    actix.yaml
    axum.yaml
    spring-boot.yaml
    rails.yaml
  community/                      # 社区贡献
    nextjs-rewrite.yaml
    nuxt.yaml
    ...

.sentinella/rules/                # 项目级规则包 (最高优先级)
  custom.yaml
```

#### 规则包 Schema

```yaml
# .sentinella/rules/nestjs.yaml
kind: rule-pack
name: nestjs
version: "1.0"
languages: [typescript]
detect:
  # 自动检测：如果项目依赖中有 @nestjs/core，自动激活此规则包
  package_json:
    dependencies: ["@nestjs/core", "@nestjs/common"]
  file_patterns: ["**/*.controller.ts", "**/*.module.ts"]

# ── 路由提取规则 ──
routes:
  - name: nestjs-decorator-route
    # tree-sitter query 或 regex
    type: tree-sitter
    query: |
      (decorator
        (call_expression
          function: (identifier) @method_name
          arguments: (arguments (string (string_fragment) @route_path)))
        (#match? @method_name "^(Get|Post|Put|Patch|Delete)$"))
    extract:
      method: "@method_name"    # 从 capture 中提取
      path: "@route_path"

  - name: nestjs-controller-prefix
    type: tree-sitter
    query: |
      (decorator
        (call_expression
          function: (identifier) @dec_name
          arguments: (arguments (string (string_fragment) @prefix)))
        (#eq? @dec_name "Controller"))
    extract:
      path_prefix: "@prefix"

# ── 保护证据规则 (替代硬编码 middleware_scope) ──
protection_evidence:
  - name: nestjs-class-guard
    description: "NestJS @UseGuards() on class level"
    scope: class              # class | function | file | block
    type: tree-sitter
    query: |
      (class_declaration
        (decorator
          (call_expression
            function: (identifier) @guard_name
            arguments: (arguments (_) @guard_arg)))
        (#eq? @guard_name "UseGuards")
        name: (type_identifier) @class_name)
    provides:
      kind: auth              # auth | rate-limit | audit | csrf
      confidence: 0.95
      scope_extends_to: all_methods_in_class

  - name: nestjs-method-guard
    scope: function
    type: tree-sitter
    query: |
      (method_definition
        (decorator
          (call_expression
            function: (identifier) @guard_name)
          (#eq? @guard_name "UseGuards")))
    provides:
      kind: auth
      confidence: 0.95

  - name: nestjs-public-decorator
    description: "@Public() exempts endpoint from auth"
    scope: function
    type: tree-sitter
    query: |
      (method_definition
        (decorator
          (call_expression
            function: (identifier) @dec_name)
          (#eq? @dec_name "Public")))
    provides:
      kind: auth-exempt
      confidence: 0.95

# ── 数据源识别规则 (替代硬编码 real_data_indicators) ──
data_source_evidence:
  - name: nestjs-inject-service
    type: regex
    pattern: "(?:@Inject|private\\s+readonly)\\s+\\w+Service"
    provides:
      kind: real-data
      confidence: 0.80

# ── 错误处理白名单 ──
error_handling:
  safe_ignore_patterns: []    # NestJS 没有需要特殊处理的

# ── 敏感日志排除 ──
sensitive_logging:
  safe_patterns:
    - "token expired"
    - "token invalid"
  mask_functions: []
```

另一个示例 — FastAPI 规则包：

```yaml
# .sentinella/rules/fastapi.yaml
kind: rule-pack
name: fastapi
version: "1.0"
languages: [python]
detect:
  requirements_txt: ["fastapi", "starlette"]
  pyproject_toml:
    dependencies: ["fastapi"]

routes:
  - name: fastapi-decorator-route
    type: tree-sitter
    query: |
      (decorated_definition
        (decorator
          (call
            function: (attribute
              object: (identifier) @app_var
              attribute: (identifier) @method_name)
            arguments: (argument_list
              (string (string_content) @route_path))))
        (#match? @method_name "^(get|post|put|patch|delete)$"))
    extract:
      method: "@method_name"
      path: "@route_path"

protection_evidence:
  - name: fastapi-depends-auth
    description: "FastAPI Depends() with auth function"
    scope: function
    type: tree-sitter
    query: |
      (default_parameter
        value: (call
          function: (identifier) @dep_name
          arguments: (argument_list
            (identifier) @auth_func))
        (#eq? @dep_name "Depends"))
    match_condition:
      auth_func_keywords: ["auth", "current_user", "get_user", "require", "verify", "jwt", "token"]
    provides:
      kind: auth
      confidence: 0.90

  - name: fastapi-depends-auth-class
    description: "FastAPI Depends() with auth class"
    scope: function
    type: tree-sitter
    query: |
      (default_parameter
        value: (call
          function: (identifier) @dep_name
          arguments: (argument_list
            (call function: (identifier) @auth_class)))
        (#eq? @dep_name "Depends"))
    match_condition:
      auth_class_keywords: ["Auth", "Permission", "Role"]
    provides:
      kind: auth
      confidence: 0.85

data_source_evidence:
  - name: python-sqlalchemy
    type: regex
    pattern: "(?:session|db)\\.(?:query|execute|add|delete|merge)"
    provides:
      kind: real-data
      confidence: 0.85
  - name: python-insert-into
    type: regex
    pattern: "INSERT\\s+INTO"
    provides:
      kind: real-data
      confidence: 0.90

error_handling:
  safe_ignore_patterns:
    - pattern: "\\.close\\(\\)"
      reason: "cleanup"
    - pattern: "logger\\.(?:debug|info)"
      reason: "logging never needs error check"

sensitive_logging:
  safe_patterns:
    - "token_type"
    - "token expired"
  mask_functions: ["mask_phone", "mask_email", "redact"]
```

### 4.2 抽象证据模型 (Evidence Model)

**核心思想：Scanner 不再检查"有没有 middleware"，而是检查"有没有保护证据"。**

```
┌─────────────────┐     ┌───────────────────────┐
│  Rule Pack A     │────→│                       │
│  (NestJS)        │     │   Evidence Store       │
├─────────────────┤     │                       │
│  Rule Pack B     │────→│  endpoint → [Evidence] │
│  (FastAPI)       │     │                       │
├─────────────────┤     │  Evidence {            │
│  Rule Pack C     │────→│    kind: auth|rate|..  │
│  (Custom)        │     │    confidence: 0.0-1.0 │
├─────────────────┤     │    source: rule_name    │
│  Config Override │────→│    scope: class|fn|..   │
│  (.sentinella)   │     │  }                     │
└─────────────────┘     └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │  Scanner (框架无关)     │
                        │                       │
                        │  S7: endpoint 有 auth  │
                        │      evidence? → PASS  │
                        │      无 evidence 且    │
                        │      无 exempt? → FIND │
                        │      confidence < 0.5  │
                        │      → Suspect         │
                        └───────────────────────┘
```

#### Evidence 类型

```yaml
# 保护证据类型 (Protection Evidence Kinds)
evidence_kinds:
  auth:           # 认证保护 (middleware, guard, decorator, DI)
  auth-exempt:    # 显式声明不需要认证 (@Public, auth_exceptions)
  rate-limit:     # 限流保护 (middleware, gateway, decorator)
  audit:          # 审计记录 (middleware, decorator, service call)
  csrf:           # CSRF 保护
  2fa:            # 二次验证
  soft-delete:    # 软删除 (非硬删除)
  real-data:      # 真实数据源 (API call, DB query, service injection)
  error-handled:  # 错误已处理
  safe-ignore:    # 可安全忽略的错误
```

#### Scanner 如何使用 Evidence

```rust
// 旧逻辑 (硬编码):
fn endpoint_has_auth_scope(ctx, file, line) -> bool {
    ctx.index.middleware_scopes.get(file)
        .any(|scope| line >= scope.line_start && line <= scope.line_end
             && is_auth_middleware(&scope.middleware_name))  // ← 硬编码关键字
}

// 新逻辑 (证据驱动):
fn endpoint_has_protection(ctx, file, line, kind: EvidenceKind) -> EvidenceResult {
    let evidences = ctx.evidence_store.query(file, line, kind);
    if evidences.iter().any(|e| e.kind == EvidenceKind::AuthExempt) {
        return EvidenceResult::Exempt;  // 显式豁免
    }
    match evidences.iter().map(|e| e.confidence).max() {
        Some(c) if c >= 0.8 => EvidenceResult::Protected(c),
        Some(c) if c >= 0.5 => EvidenceResult::Likely(c),
        Some(c)             => EvidenceResult::Suspect(c),
        None                => EvidenceResult::NoEvidence,
    }
}
```

### 4.3 Confidence Score + Finding 分级

每个 Finding 基于证据的 confidence 决定其可信度：

```rust
pub struct Finding {
    pub scanner: String,
    pub severity: Severity,       // Critical / Warning / Info
    pub confidence: Confidence,   // Confirmed / Likely / Suspect
    pub message: String,
    pub evidence: Vec<Evidence>,  // 支撑此 finding 的正/反证据
    pub file: Option<PathBuf>,
    pub line: Option<usize>,
    pub suggestion: Option<String>,
}

pub enum Confidence {
    Confirmed,   // >= 0.8 — 高置信度，AST 精确匹配
    Likely,      // 0.5-0.8 — 中置信度，需人工确认
    Suspect,     // < 0.5 — 低置信度，可能是误报
}
```

输出控制：

```bash
# 默认只显示 Confirmed + Likely
sentinella check

# 显示全部（包含 Suspect）
sentinella check --show-suspect

# 只显示 Confirmed
sentinella check --confirmed-only

# 最低 confidence 阈值
sentinella check --min-confidence 0.7
```

### 4.4 URL 映射层 (API Proxy Config)

替代硬编码 Next.js rewrite 解析，改为通用配置：

```yaml
# .sentinella.yaml
api_proxies:
  # Next.js rewrite 风格
  - source: "/svc/auth/:path*"
    target: "http://auth-service/:path*"
  # Nginx proxy_pass 风格
  - source: "/api/v1/:path*"
    target: "http://backend:3000/api/v1/:path*"
  # API Gateway 路由
  - source: "/gateway/:service/:path*"
    target: "http://:service/:path*"

  # 也可以自动探测（规则包提供）
  auto_detect:
    - file: "next.config.{js,ts,mjs}"
      parser: nextjs-rewrite    # 规则包提供的 parser
    - file: "nginx.conf"
      parser: nginx-proxy       # 规则包提供的 parser
    - file: "kong.yml"
      parser: kong-route
```

### 4.5 全局抑制体系

三级抑制，用户始终有最终决定权：

#### Level 1: Inline 注释抑制

```typescript
// sentinella-ignore-next-line S7 — public health endpoint
@Get('/health')

// sentinella-ignore S12 — managed by ORM migration
const table = 'legacy_users';

/* sentinella-ignore-file S1 — this is a design system demo page */
```

所有注释风格统一支持：`//`, `#`, `/* */`, `--`, `<!-- -->`

#### Level 2: 配置文件抑制

```yaml
# .sentinella.yaml
suppress:
  # 按 scanner 全局关闭
  disabled_scanners: [S5]

  # 按路径排除
  exclude_paths:
    global: ["**/*.d.ts", "**/*.spec.ts", "**/fixtures/**"]
    S1: ["**/components/ui/**"]
    S8: ["**/contracts/**"]
    S12: ["**/migrations/**"]

  # 按端点豁免 auth
  auth_exceptions:
    - path: "/health"
      methods: [GET]
    - path: "/api/auth/**"
      methods: [POST]
      reason: "public auth endpoints"
    - pattern: "/api/public/**"

  # 按操作类型调整行为
  destructive_safety:
    require_2fa: ["/user/account", "/user/data"]
    skip_internal: ["**/jobs/**", "**/cron/**"]

  # 敏感日志白名单
  sensitive_logging:
    safe_patterns: ["token expired", "token_type"]
    mask_functions: ["MaskPhone", "redact", "sanitize"]

  # Env 变量排除
  env:
    build_time_prefixes: ["NEXT_PUBLIC_", "VITE_", "REACT_APP_"]
    exclude_var_prefixes: ["GITHUB_", "VERCEL_", "NETLIFY_", "CI_"]
```

#### Level 3: Dismiss 文件（交互式标记）

```bash
# 扫描后对某条 finding 标记为误报
sentinella dismiss S7-0042 --reason "class-level guard"

# 查看已 dismiss 的 findings
sentinella dismissed list

# 撤销 dismiss
sentinella dismissed revert S7-0042
```

生成 `.sentinella-ignore.yaml`：

```yaml
# 此文件由 sentinella dismiss 命令自动维护
dismissed:
  - scanner: S7
    file: "src/orders/orders.controller.ts"
    line: 45
    pattern: "GET /orders"
    reason: "class-level @UseGuards covers all methods"
    by: "kd"
    at: "2026-04-07"
  - scanner: S12
    file: "src/db/schema.sql"
    table: "spatial_ref_sys"
    reason: "PostGIS system table"
    by: "kd"
    at: "2026-04-07"
```

### 4.6 自动技术栈探测

工具启动时自动检测项目技术栈，加载对应规则包：

```rust
fn detect_tech_stack(root: &Path) -> Vec<String> {
    let mut packs = Vec::new();

    // Node.js 生态
    if let Ok(pkg) = read_package_json(root) {
        if pkg.has_dep("@nestjs/core")    { packs.push("nestjs"); }
        if pkg.has_dep("express")         { packs.push("express"); }
        if pkg.has_dep("next")            { packs.push("nextjs"); }
        if pkg.has_dep("nuxt")            { packs.push("nuxt"); }
        if pkg.has_dep("@hono/hono")      { packs.push("hono"); }
    }

    // Python 生态
    if let Ok(req) = read_requirements(root) {
        if req.has("fastapi")     { packs.push("fastapi"); }
        if req.has("django")      { packs.push("django"); }
        if req.has("flask")       { packs.push("flask"); }
    }

    // Go 生态
    if let Ok(gomod) = read_go_mod(root) {
        if gomod.has("gin-gonic/gin")    { packs.push("gin"); }
        if gomod.has("labstack/echo")    { packs.push("echo"); }
        if gomod.has("go-chi/chi")       { packs.push("chi"); }
    }

    // Rust 生态
    if let Ok(cargo) = read_cargo_toml(root) {
        if cargo.has("actix-web")  { packs.push("actix"); }
        if cargo.has("axum")       { packs.push("axum"); }
        if cargo.has("rocket")     { packs.push("rocket"); }
    }

    // Java/Kotlin
    if let Ok(pom) = read_pom_xml(root) {
        if pom.has("spring-boot")  { packs.push("spring-boot"); }
    }

    packs
}
```

```bash
# 显示检测到的技术栈和加载的规则包
$ sentinella check --verbose
[INFO] Detected tech stack: nestjs, nextjs
[INFO] Loaded rule packs: nestjs (builtin), nextjs-rewrite (builtin)
[INFO] Loaded project config: .sentinella.yaml
[INFO] Loaded suppress rules: .sentinella-ignore.yaml
```

也可以手动指定：

```yaml
# .sentinella.yaml
rule_packs:
  - nestjs
  - nextjs-rewrite
  - custom: .sentinella/rules/our-framework.yaml
```

---

## 五、执行路线图

### Phase 0：Evidence Model 基础设施（2 周）

**目标：建立证据驱动架构，替代硬编码 middleware_scope。**

| 任务 | 细节 |
|------|------|
| 定义 Evidence 类型 | `Evidence { kind, confidence, source, file, line_range }` |
| 实现 EvidenceStore | DashMap 存储，支持 `query(file, line, kind)` |
| 修改所有 Scanner | 从 `middleware_scopes.get()` 改为 `evidence_store.query()` |
| 添加 Confidence 到 Finding | `Confirmed / Likely / Suspect` 三级 |
| 添加 `--min-confidence` CLI | 默认只显示 Confirmed + Likely |

**不改任何检测逻辑**，只是将现有 middleware_scope 包装为 Evidence，为后续规则包做好接口。

### Phase 1：规则包引擎 + 内置规则包（3 周）

**目标：将所有硬编码框架知识迁移到 YAML 规则包。**

| 任务 | 细节 |
|------|------|
| 实现 RulePack loader | YAML 解析 → 注册到 RuleEngine |
| 实现 tree-sitter query 动态加载 | 规则包中的 query 字段在运行时编译 |
| 实现 regex rule 执行器 | 规则包中的 regex 字段编译并执行 |
| 迁移 TypeScript 硬编码 | Express + NestJS → `express.yaml` + `nestjs.yaml` |
| 迁移 Python 硬编码 | FastAPI → `fastapi.yaml`，同时新增 `django.yaml` |
| 迁移 Go 硬编码 | Gin + Echo → `gin.yaml` + `echo.yaml` |
| 迁移 Rust 硬编码 | Actix + Axum → `actix.yaml` + `axum.yaml` |
| 实现自动技术栈探测 | `detect_tech_stack()` 读取 package.json / go.mod 等 |
| 迁移所有 const 关键字 | AUTH_KEYWORDS, TOKEN_KEYWORDS 等 → 规则包默认值 + 配置覆盖 |

迁移后，Rust 核心代码中不再有任何框架名称或框架特有模式。

### Phase 2：全局抑制体系（1-2 周）

**目标：用户可以在不修改工具代码的情况下消除所有误报。**

| 任务 | 细节 |
|------|------|
| Inline suppression 解析 | `// sentinella-ignore` 注释扫描 |
| 配置文件 suppress 加载 | `exclude_paths`, `auth_exceptions`, `disabled_scanners` |
| `sentinella dismiss` CLI | 交互式标记 finding 为误报 |
| `.sentinella-ignore.yaml` 读写 | dismiss 持久化 |
| per-scanner exclude_paths | 每个 scanner 可独立配置排除路径 |

### Phase 3：Scanner 逻辑配置化（2 周）

**目标：将 Scanner 的判定条件从 Rust 常量迁移到可配置参数。**

| Scanner | 当前硬编码 | 配置化后 |
|---------|----------|---------|
| S7 | `AUTH_KEYWORDS = [...]` | 规则包 `protection_evidence[].match_condition.keywords` |
| S13 | 所有 DELETE 要求 2FA | `destructive_safety.require_2fa` 路径匹配 |
| S18 | 任何 UPDATE 要求 token 失效 | `token_invalidation.trigger_fields` 配置 |
| S20 | 关键字匹配 = 敏感日志 | `sensitive_logging.safe_patterns` + `mask_functions` |
| S17 | Go `_ = err` 全报 | `error_handling.safe_ignore_patterns` |
| S11 | 不区分构建时/运行时 env | `env.build_time_prefixes` |
| S1 | 固定 real_data_indicators | `data_source_evidence[]` 规则包 |
| S12 | 裸表名匹配 | `data_isolation.schema_prefix` + 规则包 |
| S22 | 只看端点文件限流 | `protection_evidence[kind=rate-limit]` 支持 Gateway 级 |
| S23 | 要求函数内审计调用 | `protection_evidence[kind=audit]` 支持中间件级 |

### Phase 4：跨平台扩展 + 社区生态（持续）

| 任务 | 细节 |
|------|------|
| Spring Boot 规则包 | `@PreAuthorize`, `@Secured`, `SecurityFilterChain` |
| Rails 规则包 | `before_action :authenticate_user!`, Pundit/CanCanCan |
| Django 规则包 | `@login_required`, `PermissionRequiredMixin`, DRF permissions |
| Laravel 规则包 | `middleware('auth')`, `$this->authorize()`, Policy |
| `sentinella init --detect` | 自动生成适合当前项目的 `.sentinella.yaml` |
| 规则包 registry | `sentinella pack install spring-boot` |
| 规则包验证 CLI | `sentinella pack validate my-rules.yaml` |
| 文档 + 贡献指南 | 如何为新框架编写规则包 |

---

## 六、具体误报修复映射

将原计划中的每个误报修复映射到新架构中的解决层：

| 误报根因 | 旧方案 (写 Rust) | 新方案 (泛化) | 解决层 |
|----------|-----------------|-------------|--------|
| NestJS 类级 @UseGuards 不识别 | 修改 TS parser | `nestjs.yaml` 规则包 `protection_evidence` | Phase 1 |
| Python Depends(auth) 不识别 | 修改 Python parser | `fastapi.yaml` 规则包 `protection_evidence` | Phase 1 |
| Go .Use(authMiddleware) 不识别 | 修改 Go parser | `gin.yaml` / `echo.yaml` 规则包 | Phase 1 |
| Next.js rewrite 不追踪 | 修改 TS parser | `api_proxies` 配置 + `nextjs-rewrite.yaml` | Phase 1 |
| schema.table 不匹配 | 修改 S12 正则 | `data_isolation.schema_prefix` 配置 | Phase 2 |
| 所有 DELETE 要求 2FA | 修改 S13 逻辑 | `destructive_safety` 配置 | Phase 3 |
| 任何 UPDATE 要求 token 失效 | 修改 S18 逻辑 | `token_invalidation.trigger_fields` 配置 | Phase 3 |
| 关键字 token = 敏感日志 | 修改 S20 正则 | `sensitive_logging.safe_patterns` 配置 | Phase 2 |
| Go `_ = err` 全报 | 修改 S17 | `error_handling.safe_ignore_patterns` 配置 | Phase 3 |
| .d.ts 类型文件误判 | 修改排除逻辑 | `exclude_paths` per-scanner 配置 | Phase 2 |
| placeholder HTML 属性 | 修改 S1 正则 | `stub_indicators` 配置 + context-aware regex | Phase 3 |
| NEXT_PUBLIC_* 混淆 | 修改 S11 | `env.build_time_prefixes` 配置 | Phase 2 |
| Gateway 限流不识别 | 修改 S22 | `protection_evidence[kind=rate-limit]` | Phase 1 |
| 审计中间件不识别 | 修改 S23 | `protection_evidence[kind=audit]` | Phase 1 |
| 合法公开端点无 auth | 修改 S7 | `auth_exceptions` 配置 | Phase 2 |
| Redis DEL 不识别为 OTP 消费 | 修改 S19 | 规则包 `otp_consumption_patterns` | Phase 1 |
| hook import 链不追踪 | 修改 S1 | `data_source_evidence` 规则包 + import chain | Phase 1/3 |

---

## 七、预期效果

### 误报率下降

| Phase | 投入 | 误报率 | 关键收益 |
|-------|------|--------|---------|
| Phase 0 | 2 周 | 87% → 87% | 架构就绪，无功能变化 |
| Phase 1 | 3 周 | 87% → ~30% | 规则包覆盖 S7/S9/S1/S22/S23 |
| Phase 2 | 1-2 周 | 30% → ~15% | 抑制体系 + 配置排除 |
| Phase 3 | 2 周 | 15% → ~5% | Scanner 逻辑配置化 |
| Phase 4 | 持续 | <5% | 社区规则包持续扩展 |

### 泛化能力提升

| 指标 | 当前 | Phase 1-3 后 |
|------|------|-------------|
| 支持新框架所需工作 | 修改 Rust 代码 + 重编译 | 写一个 YAML 文件 |
| 用户消除误报的方式 | 无 | inline ignore + 配置 + dismiss |
| 框架知识位置 | 散布在 20+ Rust 文件 | 集中在 rules/ 目录 |
| 社区贡献门槛 | 需会 Rust + tree-sitter | 只需会 YAML + 正则/tree-sitter query |
| 跨技术栈适配 | 手动修改 | 自动探测 + 规则包匹配 |

### 设计原则对照

| 原则 | 当前 | 优化后 |
|------|------|--------|
| 有罪推定 vs 无罪推定 | 不理解 = Critical | 不理解 = Suspect (confidence < 0.5) |
| 单文件视野 vs 跨文件 | 只看单文件 AST | Evidence 支持 class/file/module scope |
| 硬编码 vs 可配置 | 规则写死在 Rust | 三级覆盖：用户 > 规则包 > 默认 |
| 单向证据 vs 双向证据 | 只找"没保护" | 同时找"已保护"和"未保护" |
| 误报无出口 vs 反馈闭环 | 永远重复 | ignore + dismiss + confidence 过滤 |

---

## 八、统一实施路线图（Rule Pack + Knowledge Base）

本优化计划（Rule Pack 系统）与 [Knowledge Base 持续学习架构](KNOWLEDGE_BASE_ARCHITECTURE.md) 是互补的上下层关系：

```
Layer 4: Knowledge Base (学习层)  ← KNOWLEDGE_BASE_ARCHITECTURE.md
  — Context Memory, Bayesian Calibration, Pattern Mining
  — 从反馈中自动改进，越用越准

Layer 3: Suppress System (抑制层)  ← 本文档 Phase 2
  — Inline ignore, config exclude, dismiss
  — 用户手动消除已知误报

Layer 2: Rule Pack Engine (规则层)  ← 本文档 Phase 1
  — YAML 规则包, 框架知识声明
  — 支持新框架无需改代码

Layer 1: Core Engine (引擎层)  ← 本文档 Phase 0
  — Evidence Model, Confidence, 框架无关扫描基础设施

Layer 0: Indexer (索引层)  ← 现有架构
  — 文件发现, tree-sitter AST, DashMap 存储
```

### 统一 Phase 编号

将原 Rule Pack Phase 0-4 和 Knowledge Base KB-0 到 KB-7 合并为一条时间线：

| 统一 Phase | 内容 | 来源 | 工作量 | 依赖 | 里程碑 |
|-----------|------|------|--------|------|--------|
| **P0** | Evidence Model + Finding Identity | RP Phase 0 + KB-0 | 2-3 周 | 无 | Finding 可追踪、证据驱动架构就绪 |
| **P1** | Rule Pack Engine + 内置规则包 | RP Phase 1 | 3 周 | P0 | 框架知识全部外移到 YAML |
| **P2** | 全局抑制体系 + Context Memory | RP Phase 2 + KB-1 | 2 周 | P0, P1 | 用户可消除误报 + 声明式上下文 |
| **P3** | Bayesian Calibration + Triage CLI | KB-2 + KB-3 | 2 周 | P0 | 置信度自动校准，交互式标注 |
| **P4** | Scanner 逻辑配置化 | RP Phase 3 | 2 周 | P1 | 10 个 scanner 的判定条件可配置 |
| **P5** | Pattern Miner + `sentinella learn` | KB-4 | 2 周 | P3 | 自动从 FP 聚类中建议规则 |
| **P6** | Rule Lifecycle (experimental → stable) | KB-5 | 1 周 | P1 | 规则成熟度管理 |
| **P7** | Cross-Scanner Correlation | KB-6 | 1 周 | P3 | 多 scanner 交叉验证提升置信度 |
| **P8** | 跨项目校准导入/导出 | KB-7 | 1 周 | P3 | 团队/社区共享校准数据 |
| **P9** | 跨平台扩展 + 社区生态 | RP Phase 4 | 持续 | P1, P6 | Spring Boot / Rails / Django / Laravel 规则包 |

**总投入：约 16-18 周（P3/P4 可并行，P5-P8 可并行）。**

### Phase 详细说明

#### P0：Evidence Model + Finding Identity（2-3 周）

合并 Rule Pack Phase 0 和 KB-0，一次性建好两个基础设施：

| 任务 | 来源 | 细节 |
|------|------|------|
| 定义 Evidence 类型 | RP | `Evidence { kind, confidence, source, file, line_range }` |
| 实现 EvidenceStore | RP | DashMap 存储，支持 `query(file, line, kind)` |
| 修改所有 Scanner | RP | 从 `middleware_scopes.get()` 改为 `evidence_store.query()` |
| 添加 Confidence 到 Finding | RP | `Confirmed / Likely / Suspect` 三级 |
| 添加 `--min-confidence` CLI | RP | 默认只显示 Confirmed + Likely |
| Finding stable_id | KB-0 | `blake3(scanner + relative_path + normalized_message)` |
| state.json 持久化 | KB-0 | 跨 run 追踪 finding 状态 (open/confirmed/fp/fixed) |

**关键决策：** Confidence 在此阶段是 Rule Pack 提供的**初始 confidence**（基于 Evidence 匹配精度），后续 P3 的 Bayesian Calibration 会在此基础上**校准**为最终 confidence。

```
初始 confidence (P0, Rule Pack 提供)
  × 校准系数 (P3, Bayesian 后验)
  × 相关性系数 (P7, Cross-Scanner Correlation)
  ─────────────────────────────
  = 最终 confidence (展示给用户)
```

#### P1：Rule Pack Engine + 内置规则包（3 周）

纯 Rule Pack 工作，详见本文档第四节。迁移所有框架硬编码到 YAML 规则包。

完成后 Rust 核心代码中不再有任何框架名称。

#### P2：全局抑制体系 + Context Memory（2 周）

合并 Rule Pack Phase 2 和 KB-1：

| 任务 | 来源 | 细节 |
|------|------|------|
| Inline suppression 解析 | RP | `// sentinella-ignore` 注释扫描 |
| 配置文件 suppress 加载 | RP | `exclude_paths`, `auth_exceptions`, `disabled_scanners` |
| `sentinella dismiss` CLI | RP | 交互式标记 finding 为误报 → 写入 `.sentinella/ignore.yaml` |
| Context Memory 引擎 | KB-1 | 解析 `.sentinella/memories.yaml` → 转化为 Evidence Override |
| `sentinella memory add` CLI | KB-1 | 添加项目上下文声明 |
| `sentinella memory validate` | KB-1 | 验证声明与代码是否一致 |

**两者关系：** Suppress 是"我知道这条是误报，不要再显示"（消极抑制）。Memory 是"我告诉你这个项目的特征，你据此调整判断"（积极声明）。用户可按偏好选择任一方式。

#### P3：Bayesian Calibration + Triage CLI（2 周）

可与 P4 并行。

| 任务 | 来源 | 细节 |
|------|------|------|
| calibration.json 存储 | KB-2 | per-bucket (scanner + file_glob) α/β 计数器 |
| 贝叶斯更新引擎 | KB-2 | Confirmed → α+1, FP → β+1, auto-learn-on-error only |
| 守护机制 | KB-2 | 最低样本量 (5), 90 天时间衰减, 自动桶裂变 |
| `sentinella triage` | KB-3 | 交互式标注命令，uncertainty sampling 优先展示最不确定的 |
| 冷启动 built-in priors | KB-2 | 基于三次审计数据预设高 FP 场景先验 |

完成后首次误报率即可大幅下降：Confirmed + Likely 从 6000+ 降至 ~135。

#### P4：Scanner 逻辑配置化（2 周）

可与 P3 并行。纯 Rule Pack 工作，详见本文档第五节 Phase 3。将 10 个 Scanner 的硬编码判定条件迁移到配置。

#### P5：Pattern Miner（2 周）

| 任务 | 来源 | 细节 |
|------|------|------|
| 特征提取 | KB-4 | 从 FP findings 中提取 file_extension, path_segment, message_pattern |
| 聚类算法 | KB-4 | 按 (scanner, file_pattern) 分组，FP 率 > 80% 且样本 >= 5 → 建议 |
| `sentinella learn` | KB-4 | 交互式输出建议：Add memory / Add exception / Add rule pack / Skip |
| 规则包增强建议 | KB-4 | 自动生成 rule pack YAML 片段供用户审核 |

#### P6：Rule Lifecycle（1 周）

为规则包中每条 rule 添加 `status` 字段 (experimental → testing → stable → deprecated)，自动晋升/降级条件可配置。

#### P7：Cross-Scanner Correlation（1 周）

多 scanner 交叉验证：3+ scanner 在同一文件报问题 → confidence × 1.3；孤证且该 scanner 在此 context 历史 FP > 50% → confidence × 0.6。

#### P8：跨项目校准导入/导出（1 周）

```bash
sentinella calibration export > team-calibration.json
sentinella calibration import team-calibration.json --merge
```

同技术栈项目可共享校准数据，新项目冷启动更快。

#### P9：跨平台扩展 + 社区生态（持续）

Spring Boot / Rails / Django / Laravel 规则包 + `sentinella pack install` + 社区贡献指南。

### 并行化策略

```
Week 1-3:   ████████████  P0 (Evidence Model + Finding Identity)
Week 3-6:   ████████████  P1 (Rule Pack Engine)
Week 6-8:   ████████      P2 (Suppress + Context Memory)
Week 8-10:  ████████ P3 (Bayesian)  ║  ████████ P4 (Scanner Config)  ← 并行
Week 10-12: ████████ P5 (Pattern)   ║  ████ P6 (Lifecycle)           ← 并行
Week 12-13: ████ P7 (Correlation)   ║  ████ P8 (Export/Import)       ← 并行
Week 13+:   ──────── P9 (社区生态, 持续) ────────────────────────────
```

### 预期误报率曲线（合并效果）

| Phase | 累计投入 | 误报率 | 关键收益 |
|-------|---------|--------|---------|
| P0 | 2-3 周 | 87% → 87% | 架构就绪，无功能变化 |
| P1 | 5-6 周 | 87% → ~30% | 规则包覆盖 S7/S9/S1/S22/S23 |
| P2 | 7-8 周 | 30% → ~15% | 抑制体系 + Context Memory |
| P3 | 9-10 周 | 15% → ~8% | Bayesian 校准，低置信 finding 默认隐藏 |
| P4 | 9-10 周 | 8% → ~5% | Scanner 逻辑配置化 |
| P5-P8 | 12-13 周 | 5% → ~2% | 自动学习 + 交叉验证 + 跨项目先验 |
| P9 | 持续 | <2% | 社区规则包持续扩展 |

---

## 九、设计反思总结

Sentinella 的核心价值是**跨层完整性审计** — 这个定位是对的。但当前实现把"框架知识"和"审计引擎"混在一起，导致：

1. **换个框架就废了** — 工具绑定了 Express/NestJS 的心智模型
2. **用户无法自救** — 没有任何抑制机制，误报率只能由工具开发者解决
3. **无法泛化** — 每支持一个新框架就要改 Rust 代码

**修正方向**：

> **Rust 核心做引擎（AST 遍历 + 证据收集 + 跨文件追踪），框架知识全部外移到声明式规则包。**

这不是重写，而是一次架构拆分：
- Parser 层：保留 tree-sitter 基础设施，但查询语句从编译时嵌入改为运行时从规则包加载
- Scanner 层：保留 5 层执行框架，但判定逻辑从硬编码改为配置驱动
- 新增：Evidence Store（证据仓库）、Rule Pack Engine（规则包引擎）、Suppress System（抑制系统）

**结果**：Sentinella 从"一个 Express/NestJS 审计工具"变成"一个可适配任意技术栈的审计引擎"。
