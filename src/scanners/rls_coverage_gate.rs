use crate::config::schema::RlsCoverageConfig;
use crate::indexer::types::TableInfo;
use crate::scanners::types::{Confidence, Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S29";
const SCANNER_NAME: &str = "RlsCoverageGate";
const SCANNER_DESC: &str =
    "Verifies that every tenant-sensitive table has RLS enabled and FORCE RLS active.";

pub struct RlsCoverageGate;

impl Scanner for RlsCoverageGate {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        SCANNER_NAME
    }

    fn description(&self) -> &str {
        SCANNER_DESC
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let rls_config = &ctx.config.database_security.rls_coverage;

        if !rls_config.enabled {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "RLS coverage scanning is disabled.".to_string(),
            };
        }

        let tables = ctx.index.all_db_tables();
        let findings = check_all_tables(&tables, rls_config);
        let score = compute_score(&findings);
        let summary = build_summary(&findings, score);

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

/// Iterate all tables and collect findings for tenant-sensitive tables
/// missing RLS or FORCE RLS.
fn check_all_tables(tables: &[TableInfo], config: &RlsCoverageConfig) -> Vec<Finding> {
    tables
        .iter()
        .filter(|t| is_tenant_sensitive(t, &config.tenant_columns))
        .filter(|t| !is_exempt(t, &config.exemptions))
        .flat_map(check_single_table)
        .collect()
}

/// A table is tenant-sensitive if any of its columns matches the configured
/// tenant column names (case-insensitive comparison).
fn is_tenant_sensitive(table: &TableInfo, tenant_columns: &[String]) -> bool {
    table.columns.iter().any(|col| {
        let lower = col.to_lowercase();
        tenant_columns.iter().any(|tc| tc.to_lowercase() == lower)
    })
}

/// A table is exempt if its fully-qualified name (`schema.table` or just
/// `table`) appears in the exemption list (case-insensitive).
fn is_exempt(table: &TableInfo, exemptions: &[String]) -> bool {
    let fqn = qualified_name(table);
    let plain = table.table_name.to_lowercase();

    exemptions.iter().any(|ex| {
        let ex_lower = ex.to_lowercase();
        ex_lower == fqn || ex_lower == plain
    })
}

/// Build a lowercase qualified name: `schema.table` or just `table`.
fn qualified_name(table: &TableInfo) -> String {
    match &table.schema_name {
        Some(schema) => format!(
            "{}.{}",
            schema.to_lowercase(),
            table.table_name.to_lowercase()
        ),
        None => table.table_name.to_lowercase(),
    }
}

/// Produce findings for a single tenant-sensitive, non-exempt table.
fn check_single_table(table: &TableInfo) -> Vec<Finding> {
    let label = display_name(table);
    let mut findings = Vec::new();

    if !table.has_rls {
        findings.push(
            Finding::new(
                SCANNER_ID,
                Severity::Critical,
                format!("Table `{label}` contains tenant data but has no RLS policy enabled"),
            )
            .with_suggestion(format!("ALTER TABLE {label} ENABLE ROW LEVEL SECURITY;"))
            .with_confidence(Confidence::Confirmed),
        );
    }

    if table.has_rls && !table.has_force_rls {
        findings.push(
            Finding::new(
                SCANNER_ID,
                Severity::Warning,
                format!(
                    "Table `{label}` has RLS but FORCE RLS is not active \
                     (table owners bypass policies)"
                ),
            )
            .with_suggestion(format!("ALTER TABLE {label} FORCE ROW LEVEL SECURITY;"))
            .with_confidence(Confidence::Confirmed),
        );
    }

    findings
}

/// Human-readable table reference: `schema.table` or just `table`.
fn display_name(table: &TableInfo) -> String {
    match &table.schema_name {
        Some(schema) => format!("{schema}.{}", table.table_name),
        None => table.table_name.clone(),
    }
}

/// Score starts at 100; each Critical deducts 15, each Warning deducts 5.
/// Clamped to 0..=100.
fn compute_score(findings: &[Finding]) -> u8 {
    if findings.is_empty() {
        return 100;
    }

    let deductions: f64 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => 15.0,
            Severity::Warning => 5.0,
            Severity::Info => 2.0,
        })
        .sum();

    (100.0 - deductions).max(0.0).round() as u8
}

/// Build a human-readable summary line.
fn build_summary(findings: &[Finding], score: u8) -> String {
    if findings.is_empty() {
        return "All tenant-sensitive tables have RLS and FORCE RLS enabled.".to_string();
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let warning = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();

    format!(
        "RLS coverage gaps: {critical} critical (missing RLS), \
         {warning} warning (missing FORCE RLS). Score: {score}/100."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table(name: &str, columns: &[&str], rls: bool, force_rls: bool) -> TableInfo {
        TableInfo {
            schema_name: Some("public".to_string()),
            table_name: name.to_string(),
            columns: columns.iter().map(|c| c.to_string()).collect(),
            has_rls: rls,
            has_force_rls: force_rls,
            has_partition: false,
            app_role: None,
        }
    }

    fn default_config() -> RlsCoverageConfig {
        RlsCoverageConfig::default()
    }

    #[test]
    fn clean_table_produces_no_findings() {
        let tables = vec![make_table("users", &["id", "user_id", "email"], true, true)];
        let findings = check_all_tables(&tables, &default_config());
        assert!(findings.is_empty());
    }

    #[test]
    fn missing_rls_produces_critical() {
        let tables = vec![make_table("orders", &["id", "user_id"], false, false)];
        let findings = check_all_tables(&tables, &default_config());
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert_eq!(critical.len(), 1);
        assert!(critical[0].message.contains("no RLS policy"));
    }

    #[test]
    fn missing_force_rls_produces_warning() {
        let tables = vec![make_table("sessions", &["id", "session_id"], true, false)];
        let findings = check_all_tables(&tables, &default_config());
        let warnings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("FORCE RLS"));
    }

    #[test]
    fn non_tenant_table_skipped() {
        let tables = vec![make_table("migrations", &["id", "version"], false, false)];
        let findings = check_all_tables(&tables, &default_config());
        assert!(findings.is_empty());
    }

    #[test]
    fn exempt_table_skipped() {
        let config = RlsCoverageConfig {
            enabled: true,
            tenant_columns: vec!["user_id".into()],
            exemptions: vec!["public.audit_log".into()],
        };
        let tables = vec![make_table("audit_log", &["id", "user_id"], false, false)];
        let findings = check_all_tables(&tables, &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn score_deduction_critical_only_when_no_rls() {
        let tables = vec![make_table("accounts", &["id", "user_id"], false, false)];
        let findings = check_all_tables(&tables, &default_config());
        // Only 1 Critical (-15) when both missing; Warning is suppressed
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        let score = compute_score(&findings);
        assert_eq!(score, 85);
    }

    #[test]
    fn score_clamps_to_zero() {
        // 7 Critical findings = -105 => clamped to 0
        let findings: Vec<Finding> = (0..7)
            .map(|i| Finding::new(SCANNER_ID, Severity::Critical, format!("issue {i}")))
            .collect();
        assert_eq!(compute_score(&findings), 0);
    }

    #[test]
    fn summary_clean() {
        let summary = build_summary(&[], 100);
        assert!(summary.contains("All tenant-sensitive tables"));
    }

    #[test]
    fn summary_with_findings() {
        let findings = vec![
            Finding::new(SCANNER_ID, Severity::Critical, "missing RLS"),
            Finding::new(SCANNER_ID, Severity::Warning, "missing FORCE"),
        ];
        let summary = build_summary(&findings, 80);
        assert!(summary.contains("1 critical"));
        assert!(summary.contains("1 warning"));
    }

    #[test]
    fn tenant_column_match_is_case_insensitive() {
        let table = make_table("profiles", &["ID", "User_ID", "name"], false, false);
        assert!(is_tenant_sensitive(&table, &["user_id".to_string()]));
    }

    #[test]
    fn exemption_match_is_case_insensitive() {
        let table = make_table("Audit_Log", &["id", "user_id"], false, false);
        let table_with_schema = TableInfo {
            schema_name: Some("Public".to_string()),
            ..table
        };
        assert!(is_exempt(
            &table_with_schema,
            &["public.audit_log".to_string()]
        ));
    }
}
