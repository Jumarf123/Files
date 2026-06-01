use anyhow::{Context, Result};
use csv::Writer;
use html_escape::encode_text;
use rss_core::{ArtifactRecord, ScanSnapshot};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBundle {
    pub json_path: String,
    pub csv_path: String,
    pub html_path: String,
    pub dfxml_path: String,
}

pub fn export_reports(snapshot: &ScanSnapshot, destination: &str) -> Result<ReportBundle> {
    fs::create_dir_all(destination).with_context(|| format!("Failed to create {}", destination))?;
    let stem = format!("files-{}", snapshot.summary.scan_id);
    let json_path = Path::new(destination).join(format!("{stem}.json"));
    let csv_path = Path::new(destination).join(format!("{stem}.csv"));
    let html_path = Path::new(destination).join(format!("{stem}.html"));
    let dfxml_path = Path::new(destination).join(format!("{stem}.dfxml.xml"));

    fs::write(&json_path, serde_json::to_vec_pretty(snapshot)?)
        .with_context(|| format!("Failed to write {}", json_path.display()))?;
    write_csv(&csv_path, &snapshot.results)?;
    fs::write(&html_path, build_html(snapshot))
        .with_context(|| format!("Failed to write {}", html_path.display()))?;
    fs::write(&dfxml_path, build_dfxml(snapshot))
        .with_context(|| format!("Failed to write {}", dfxml_path.display()))?;

    Ok(ReportBundle {
        json_path: json_path.display().to_string(),
        csv_path: csv_path.display().to_string(),
        html_path: html_path.display().to_string(),
        dfxml_path: dfxml_path.display().to_string(),
    })
}

fn write_csv(path: &PathBuf, results: &[ArtifactRecord]) -> Result<()> {
    let mut writer = Writer::from_path(path)?;
    writer.write_record([
        "id",
        "name",
        "path",
        "kind",
        "family",
        "origin_type",
        "confidence",
        "recoverability",
        "size",
        "record_number",
        "raw_offset",
    ])?;

    for artifact in results {
        writer.write_record([
            artifact.id.as_str(),
            artifact.name.as_str(),
            artifact.original_path.as_deref().unwrap_or(""),
            &format!("{:?}", artifact.kind),
            &format!("{:?}", artifact.family),
            &format!("{:?}", artifact.origin_type),
            &format!("{:?}", artifact.confidence),
            &format!("{:?}", artifact.recoverability),
            &artifact.size.to_string(),
            &artifact
                .filesystem_record
                .map(|value| value.to_string())
                .unwrap_or_default(),
            &artifact
                .raw_offset
                .map(|value| format!("{value:#x}"))
                .unwrap_or_default(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn build_html(snapshot: &ScanSnapshot) -> String {
    let rows = snapshot
        .results
        .iter()
        .map(|artifact| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:?}</td><td>{:?}</td><td>{}</td></tr>",
                encode_text(&artifact.name),
                encode_text(artifact.original_path.as_deref().unwrap_or("-")),
                encode_text(&format!("{:?}", artifact.kind)),
                artifact.confidence,
                artifact.recoverability,
                artifact.size
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Files report</title>
  <style>
    body {{ font-family: "Segoe UI", sans-serif; background: #0d1117; color: #e6edf3; margin: 40px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 24px; }}
    th, td {{ border-bottom: 1px solid #30363d; text-align: left; padding: 10px; font-size: 13px; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 16px; padding: 20px; margin-bottom: 16px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Files Scan Report</h1>
    <p><strong>Scan:</strong> {scan_id}</p>
    <p><strong>Source:</strong> {source}</p>
    <p><strong>Status:</strong> {status:?}</p>
    <p><strong>Results:</strong> {count}</p>
  </div>
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Original Path</th>
        <th>Kind</th>
        <th>Confidence</th>
        <th>Recoverability</th>
        <th>Size</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"#,
        scan_id = encode_text(&snapshot.summary.scan_id),
        source = encode_text(&snapshot.summary.source_name),
        status = snapshot.summary.status,
        count = snapshot.results.len(),
    )
}

fn build_dfxml(snapshot: &ScanSnapshot) -> String {
    let entries = snapshot
        .results
        .iter()
        .map(|artifact| {
            format!(
                "<fileobject><filename>{}</filename><filesize>{}</filesize><hashdigest type=\"sha256\"></hashdigest><meta><kind>{:?}</kind><confidence>{:?}</confidence><recoverability>{:?}</recoverability><origin>{:?}</origin></meta></fileobject>",
                xml_escape(artifact.original_path.as_deref().unwrap_or(&artifact.name)),
                artifact.size,
                artifact.kind,
                artifact.confidence,
                artifact.recoverability,
                artifact.origin_type
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<dfxml xmloutputversion="1.1">
  <metadata>
    <source>{}</source>
    <scan_id>{}</scan_id>
    <status>{:?}</status>
  </metadata>
  <source_path>{}</source_path>
  {}
</dfxml>"#,
        xml_escape(&snapshot.summary.source_name),
        xml_escape(&snapshot.summary.scan_id),
        snapshot.summary.status,
        xml_escape(&snapshot.source.device_path),
        entries
    )
}

fn xml_escape(value: &str) -> String {
    encode_text(value)
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::{build_dfxml, build_html};
    use rss_core::{
        ArtifactClass, ArtifactKind, ArtifactRecord, Confidence, ContentSourceKind, FileSystemKind,
        NameSourceKind, OriginType, PathConfidence, PlacementKind, PreviewFact, Recoverability,
        RecoveryPlan, ScanCounters, ScanMode, ScanProgress, ScanSnapshot, ScanSource, ScanStatus,
        ScanSummary, SourceKind,
    };

    fn fixture_snapshot() -> ScanSnapshot {
        ScanSnapshot {
            summary: ScanSummary {
                scan_id: "scan-1".to_string(),
                source_id: "source-1".to_string(),
                source_name: "System NVMe (C:)".to_string(),
                mode: ScanMode::Fast,
                filesystem: FileSystemKind::Ntfs,
                status: ScanStatus::Completed,
                started_at: "2026-03-10T10:00:00Z".to_string(),
                finished_at: Some("2026-03-10T10:00:30Z".to_string()),
                duration_seconds: Some(30),
                warnings: vec![],
                counters: ScanCounters {
                    total_results: 1,
                    executable_results: 1,
                    archive_results: 0,
                    script_results: 0,
                    carved_results: 0,
                    partial_results: 0,
                    recoverable_results: 1,
                },
            },
            source: ScanSource {
                id: "source-1".to_string(),
                kind: SourceKind::LogicalVolume,
                device_path: r"\\.\C:".to_string(),
                mount_point: Some(r"C:\".to_string()),
                display_name: "System NVMe (C:)".to_string(),
                volume_label: Some("Windows".to_string()),
                filesystem: FileSystemKind::Ntfs,
                volume_serial: Some(0x4f2a17c1),
                total_bytes: 100,
                free_bytes: 50,
                cluster_size: Some(4096),
                is_system: true,
                requires_elevation: true,
            },
            progress: ScanProgress {
                scan_id: "scan-1".to_string(),
                status: ScanStatus::Completed,
                phase: rss_core::ScanPhase::Finalizing,
                stage: "finalize".to_string(),
                progress_percent: 100.0,
                files_examined: 1,
                artifacts_found: 1,
                records_scanned: 1,
                candidates_surfaced: 1,
                validated_hits: 1,
                named_hits: 1,
                carved_hits: 0,
                fragment_hits: 0,
                verified_hits: 1,
                recoverable_hits: 1,
                bytes_scanned: 100,
                records_per_second: 0.0,
                eta_seconds: Some(0),
                target_sla_seconds: 40,
                raw_evidence_state: rss_core::RawEvidenceState::NotStarted,
                message: "Done".to_string(),
                stage_timing_ms: std::collections::BTreeMap::new(),
                started_at: "2026-03-10T10:00:00Z".to_string(),
                last_progress_at: "2026-03-10T10:00:30Z".to_string(),
                updated_at: "2026-03-10T10:00:30Z".to_string(),
            },
            results: vec![ArtifactRecord {
                id: "artifact-1".to_string(),
                scan_id: "scan-1".to_string(),
                source_id: "source-1".to_string(),
                name: "payload.exe".to_string(),
                original_path: Some(r"C:\Users\Public\payload.exe".to_string()),
                probable_path: None,
                placement_kind: PlacementKind::OriginalPath,
                path_confidence: PathConfidence::Exact,
                path_evidence: Vec::new(),
                name_source: NameSourceKind::LongName,
                content_source: ContentSourceKind::RawRuns,
                artifact_class: ArtifactClass::ValidatedHit,
                preview_ready: true,
                is_fragment: false,
                fragment_id: None,
                extension: Some("exe".to_string()),
                family: ArtifactKind::Exe.family(),
                kind: ArtifactKind::Exe,
                origin_type: OriginType::FilesystemDeletedEntry,
                confidence: Confidence::High,
                recoverability: Recoverability::Good,
                deleted_entry: true,
                size: 1024,
                priority_score: 100,
                filesystem_record: Some(42),
                parent_reference: Some(5),
                raw_offset: Some(0x1000),
                raw_length: Some(2048),
                created_at: None,
                modified_at: None,
                deleted_at: None,
                deleted_time_source: None,
                deleted_time_confidence: rss_core::DeletedTimeConfidence::Unknown,
                last_metadata_change_at: None,
                notes: vec!["PE validated".to_string()],
                preview: vec![PreviewFact {
                    label: "Machine".to_string(),
                    value: "x64".to_string(),
                }],
                recovery_plan: RecoveryPlan::Unrecoverable {
                    reason: "fixture".to_string(),
                },
            }],
        }
    }

    #[test]
    fn html_report_contains_primary_scan_values() {
        let html = build_html(&fixture_snapshot());
        assert!(html.contains("Files Scan Report"));
        assert!(html.contains("payload.exe"));
        assert!(html.contains("System NVMe (C:)"));
    }

    #[test]
    fn dfxml_contains_filename_and_origin_metadata() {
        let dfxml = build_dfxml(&fixture_snapshot());
        assert!(dfxml.contains("<scan_id>scan-1</scan_id>"));
        assert!(dfxml.contains("payload.exe"));
        assert!(dfxml.contains("FilesystemDeletedEntry"));
    }
}
