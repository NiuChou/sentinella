use std::collections::HashSet;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S10";

pub struct EventSchemaDrift;

impl Scanner for EventSchemaDrift {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        "Event Schema Drift"
    }

    fn description(&self) -> &str {
        "Detects event contract drift between producers and consumers"
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let mut findings = Vec::new();

        let producer_topics = collect_topics(&ctx.index.event_producers);
        let consumer_topics = collect_topics(&ctx.index.event_consumers);

        if producer_topics.is_empty() && consumer_topics.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No event producers or consumers found".to_string(),
            };
        }

        // Unhandled events: produced but not consumed
        for topic in &producer_topics {
            if !consumer_topics.contains(topic) && !has_fuzzy_consumer(topic, &consumer_topics) {
                let producer_entries = ctx.index.event_producers.get(topic);
                if let Some(entries) = producer_entries {
                    for entry in entries.value() {
                        findings.push(
                            Finding::new(
                                SCANNER_ID,
                                Severity::Warning,
                                format!(
                                    "Unhandled event: topic '{}' is produced but has no consumer",
                                    topic
                                ),
                            )
                            .with_file(entry.file.clone())
                            .with_line(entry.line)
                            .with_suggestion(
                                "Add a consumer for this event or remove the producer if obsolete",
                            ),
                        );
                    }
                }
            }
        }

        // Dead listeners: consumed but not produced
        for topic in &consumer_topics {
            if !producer_topics.contains(topic) && !has_fuzzy_producer(topic, &producer_topics) {
                let consumer_entries = ctx.index.event_consumers.get(topic);
                if let Some(entries) = consumer_entries {
                    for entry in entries.value() {
                        findings.push(
                            Finding::new(
                                SCANNER_ID,
                                Severity::Critical,
                                format!(
                                    "Dead listener: topic '{}' is consumed but has no producer",
                                    topic
                                ),
                            )
                            .with_file(entry.file.clone())
                            .with_line(entry.line)
                            .with_suggestion("Remove the dead listener or add a matching producer"),
                        );
                    }
                }
            }
        }

        // Naming drift: topics that match by suffix but differ by prefix
        let naming_drift_findings = detect_naming_drift(ctx, &producer_topics, &consumer_topics);
        findings.extend(naming_drift_findings);

        let all_topics: HashSet<&String> = producer_topics.union(&consumer_topics).collect();
        let aligned_count = producer_topics
            .iter()
            .filter(|t| consumer_topics.contains(*t))
            .count();
        let total = all_topics.len();

        let score = compute_score(&findings);

        let summary = format!(
            "{} topics total, {} aligned, {} unhandled, {} dead listeners, {} naming drifts",
            total,
            aligned_count,
            producer_topics
                .iter()
                .filter(|t| !consumer_topics.contains(*t))
                .count(),
            consumer_topics
                .iter()
                .filter(|t| !producer_topics.contains(*t))
                .count(),
            findings
                .iter()
                .filter(|f| f.message.contains("Naming drift"))
                .count(),
        );

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

/// Compute score using a graduated penalty model.
///
/// Each finding deducts from 100 based on severity:
/// - Critical: -15
/// - Warning: -8
/// - Info: -3
///
/// The score floors at 0.
fn compute_score(findings: &[Finding]) -> u8 {
    let penalty: i32 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => 15,
            Severity::Warning => 8,
            Severity::Info => 3,
        })
        .sum();
    let raw = 100i32.saturating_sub(penalty);
    raw.max(0) as u8
}

/// Collect all unique topic names from a DashMap keyed by topic.
fn collect_topics<V>(map: &dashmap::DashMap<String, Vec<V>>) -> HashSet<String> {
    map.iter().map(|entry| entry.key().clone()).collect()
}

/// Check if a producer topic has a fuzzy match in the consumer topics.
/// Handles cases like "asset.created" matching "plm.asset.created".
fn has_fuzzy_consumer(producer_topic: &str, consumer_topics: &HashSet<String>) -> bool {
    consumer_topics
        .iter()
        .any(|ct| ct.ends_with(producer_topic) || producer_topic.ends_with(ct.as_str()))
}

/// Check if a consumer topic has a fuzzy match in the producer topics.
fn has_fuzzy_producer(consumer_topic: &str, producer_topics: &HashSet<String>) -> bool {
    producer_topics
        .iter()
        .any(|pt| pt.ends_with(consumer_topic) || consumer_topic.ends_with(pt.as_str()))
}

/// Detect naming drift: topics that share a suffix but differ by a namespace prefix.
/// e.g., producer emits "asset.created" but consumer listens on "plm.asset.created".
fn detect_naming_drift(
    ctx: &ScanContext,
    producer_topics: &HashSet<String>,
    consumer_topics: &HashSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for pt in producer_topics {
        if consumer_topics.contains(pt) {
            continue;
        }
        for ct in consumer_topics {
            if ct == pt {
                continue;
            }
            let is_suffix_match = ct.ends_with(pt.as_str()) || pt.ends_with(ct.as_str());
            if !is_suffix_match {
                continue;
            }
            // Found a naming drift pair
            let producer_file = ctx
                .index
                .event_producers
                .get(pt)
                .and_then(|entries| entries.value().first().map(|e| (e.file.clone(), e.line)));
            let consumer_file = ctx
                .index
                .event_consumers
                .get(ct)
                .and_then(|entries| entries.value().first().map(|e| (e.file.clone(), e.line)));

            let mut finding = Finding::new(
                SCANNER_ID,
                Severity::Warning,
                format!(
                    "Naming drift: producer uses '{}' but consumer uses '{}'",
                    pt, ct
                ),
            )
            .with_suggestion(format!(
                "Align topic names: use either '{}' or '{}' consistently",
                pt, ct
            ));

            if let Some((file, line)) = producer_file {
                finding = finding.with_file(file).with_line(line);
            } else if let Some((file, line)) = consumer_file {
                finding = finding.with_file(file).with_line(line);
            }

            findings.push(finding);
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::types::EventProducer;
    use std::path::PathBuf;

    #[test]
    fn test_has_fuzzy_consumer_suffix_match() {
        let consumers: HashSet<String> =
            vec!["plm.asset.created".to_string()].into_iter().collect();
        assert!(has_fuzzy_consumer("asset.created", &consumers));
    }

    #[test]
    fn test_has_fuzzy_consumer_no_match() {
        let consumers: HashSet<String> = vec!["order.shipped".to_string()].into_iter().collect();
        assert!(!has_fuzzy_consumer("asset.created", &consumers));
    }

    #[test]
    fn test_collect_topics_empty() {
        let map: dashmap::DashMap<String, Vec<EventProducer>> = dashmap::DashMap::new();
        let topics = collect_topics(&map);
        assert!(topics.is_empty());
    }

    #[test]
    fn test_single_finding_does_not_zero_score() {
        // One Warning finding should deduct 8 points, yielding 92
        let findings = vec![Finding::new(
            SCANNER_ID,
            Severity::Warning,
            "Unhandled event: topic 'asset.created' is produced but has no consumer",
        )];
        let score = compute_score(&findings);
        assert!(
            score >= 60,
            "Single Warning finding should not zero the score, got {}",
            score
        );
        assert_eq!(score, 92);
    }

    #[test]
    fn test_compute_score_mixed_severities() {
        let findings = vec![
            Finding::new(SCANNER_ID, Severity::Critical, "dead listener"),
            Finding::new(SCANNER_ID, Severity::Warning, "unhandled event"),
            Finding::new(SCANNER_ID, Severity::Info, "naming drift"),
        ];
        // 100 - 15 - 8 - 3 = 74
        assert_eq!(compute_score(&findings), 74);
    }

    #[test]
    fn test_compute_score_floors_at_zero() {
        let findings: Vec<Finding> = (0..10)
            .map(|_| Finding::new(SCANNER_ID, Severity::Critical, "dead listener"))
            .collect();
        // 100 - 150 = -50, clamped to 0
        assert_eq!(compute_score(&findings), 0);
    }

    #[test]
    fn test_collect_topics_populated() {
        let map: dashmap::DashMap<String, Vec<EventProducer>> = dashmap::DashMap::new();
        map.insert(
            "asset.created".to_string(),
            vec![EventProducer {
                topic: "asset.created".to_string(),
                file: PathBuf::from("src/events.rs"),
                line: 10,
            }],
        );
        let topics = collect_topics(&map);
        assert_eq!(topics.len(), 1);
        assert!(topics.contains("asset.created"));
    }
}
