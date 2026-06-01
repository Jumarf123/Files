use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use blake3::Hasher as Blake3;
use rss_core::{
    ArtifactRecord, RecoveryItemResult, RecoveryPlan, RecoveryRequest, RecoveryStatus,
    RecoverySummary, now_iso,
};
use rss_windows::open_raw_readonly;
use sanitize_filename::sanitize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub fn recover_selected(
    artifacts: &[ArtifactRecord],
    request: &RecoveryRequest,
) -> Result<RecoverySummary> {
    fs::create_dir_all(&request.destination)
        .with_context(|| format!("Failed to create {}", request.destination))?;

    let started_at = now_iso();
    let mut items = Vec::new();
    for artifact in artifacts {
        items.push(recover_one(artifact, &request.destination)?);
    }

    Ok(RecoverySummary {
        scan_id: request.scan_id.clone(),
        destination: request.destination.clone(),
        started_at,
        finished_at: now_iso(),
        items,
    })
}

fn recover_one(artifact: &ArtifactRecord, destination: &str) -> Result<RecoveryItemResult> {
    match &artifact.recovery_plan {
        RecoveryPlan::Unrecoverable { reason } => Ok(RecoveryItemResult {
            artifact_id: artifact.id.clone(),
            file_path: None,
            metadata_path: None,
            sha256: None,
            blake3: None,
            status: RecoveryStatus::Unrecoverable,
            notes: vec![reason.clone()],
        }),
        RecoveryPlan::ResidentBase64 {
            base64,
            logical_size,
        } => {
            let bytes = BASE64
                .decode(base64)
                .context("Resident data could not be decoded")?;
            let recovered = bytes
                .into_iter()
                .take(*logical_size as usize)
                .collect::<Vec<_>>();
            persist_recovered(
                artifact,
                destination,
                &recovered,
                RecoveryStatus::Recovered,
                Vec::new(),
            )
        }
        RecoveryPlan::RawRuns {
            source_path,
            runs,
            logical_size,
        } => {
            let target_path = unique_output_path(destination, &artifact.name);
            let mut output = File::create(&target_path)
                .with_context(|| format!("Failed to create {}", target_path.display()))?;
            let mut source = open_raw_readonly(source_path)?;
            let mut remaining = *logical_size;
            let mut hasher = Sha256::new();
            let mut blake = Blake3::new();
            let mut notes = Vec::new();

            for run in runs {
                let to_copy = remaining.min(run.length);
                if to_copy == 0 {
                    break;
                }

                if run.sparse {
                    let zeroes =
                        vec![0u8; usize::try_from(to_copy.min(1 << 20)).unwrap_or(1 << 20)];
                    let mut left = to_copy;
                    while left > 0 {
                        let chunk = left.min(zeroes.len() as u64) as usize;
                        output.write_all(&zeroes[..chunk])?;
                        hasher.update(&zeroes[..chunk]);
                        blake.update(&zeroes[..chunk]);
                        left -= chunk as u64;
                    }
                    notes.push("Sparse NTFS run materialized as zeroes.".to_string());
                } else {
                    source
                        .seek(SeekFrom::Start(run.offset))
                        .with_context(|| format!("Failed to seek to {:#x}", run.offset))?;
                    copy_n(&mut source, &mut output, to_copy, &mut hasher, &mut blake)?;
                }
                remaining -= to_copy;
            }

            let sha256 = format!("{:x}", hasher.finalize());
            let blake3 = blake.finalize().to_hex().to_string();
            let status = if remaining == 0 {
                if notes.is_empty() {
                    RecoveryStatus::Recovered
                } else {
                    RecoveryStatus::RecoveredWithWarnings
                }
            } else {
                notes.push(format!(
                    "Recovery stopped early with {remaining} bytes missing from the logical size."
                ));
                RecoveryStatus::Partial
            };

            let metadata_path =
                write_metadata(artifact, &target_path, &sha256, &blake3, status, &notes)?;

            Ok(RecoveryItemResult {
                artifact_id: artifact.id.clone(),
                file_path: Some(target_path.display().to_string()),
                metadata_path: Some(metadata_path.display().to_string()),
                sha256: Some(sha256),
                blake3: Some(blake3),
                status,
                notes,
            })
        }
    }
}

fn persist_recovered(
    artifact: &ArtifactRecord,
    destination: &str,
    bytes: &[u8],
    status: RecoveryStatus,
    notes: Vec<String>,
) -> Result<RecoveryItemResult> {
    let target_path = unique_output_path(destination, &artifact.name);
    fs::write(&target_path, bytes)
        .with_context(|| format!("Failed to write {}", target_path.display()))?;

    let sha256 = format!("{:x}", Sha256::digest(bytes));
    let blake3 = blake3::hash(bytes).to_hex().to_string();
    let metadata_path = write_metadata(artifact, &target_path, &sha256, &blake3, status, &notes)?;

    Ok(RecoveryItemResult {
        artifact_id: artifact.id.clone(),
        file_path: Some(target_path.display().to_string()),
        metadata_path: Some(metadata_path.display().to_string()),
        sha256: Some(sha256),
        blake3: Some(blake3),
        status,
        notes,
    })
}

fn copy_n(
    source: &mut File,
    target: &mut File,
    mut bytes: u64,
    sha256: &mut Sha256,
    blake3: &mut Blake3,
) -> Result<()> {
    let mut buffer = vec![0u8; 1 << 20];
    while bytes > 0 {
        let chunk = bytes.min(buffer.len() as u64) as usize;
        source.read_exact(&mut buffer[..chunk])?;
        target.write_all(&buffer[..chunk])?;
        sha256.update(&buffer[..chunk]);
        blake3.update(&buffer[..chunk]);
        bytes -= chunk as u64;
    }
    Ok(())
}

fn unique_output_path(destination: &str, name: &str) -> PathBuf {
    let sanitized = sanitize(name);
    let path = Path::new(destination).join(&sanitized);
    if !path.exists() {
        return path;
    }

    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("recovered")
        .to_string();
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_string();
    for index in 1..1000 {
        let candidate = if ext.is_empty() {
            format!("{stem}_{index}")
        } else {
            format!("{stem}_{index}.{ext}")
        };
        let candidate_path = Path::new(destination).join(candidate);
        if !candidate_path.exists() {
            return candidate_path;
        }
    }

    Path::new(destination).join(format!("{}_{}", stem, artifact_safe_suffix()))
}

fn artifact_safe_suffix() -> String {
    now_iso().replace(':', "-")
}

fn write_metadata(
    artifact: &ArtifactRecord,
    recovered_path: &Path,
    sha256: &str,
    blake3: &str,
    status: RecoveryStatus,
    notes: &[String],
) -> Result<PathBuf> {
    let metadata_path = recovered_path.with_extension(format!(
        "{}.metadata.json",
        recovered_path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("bin")
    ));

    let payload = json!({
        "artifact": artifact,
        "recovered_at": now_iso(),
        "recovered_path": recovered_path.display().to_string(),
        "sha256": sha256,
        "blake3": blake3,
        "status": status,
        "notes": notes,
    });
    fs::write(&metadata_path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("Failed to write {}", metadata_path.display()))?;
    Ok(metadata_path)
}
