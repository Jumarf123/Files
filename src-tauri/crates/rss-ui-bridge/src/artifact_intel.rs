use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cfb::CompoundFile;
use chardetng::EncodingDetector;
use encoding_rs_io::DecodeReaderBytesBuilder;
use rss_core::{
    ArchivePreviewEntry, ArchivePreviewEntryStatus, ArchivePreviewPage, ArtifactKind,
    ArtifactPreviewMode, ArtifactPreviewRequest, ArtifactPreviewResponse, ArtifactRecord,
    ArtifactSignatureStatus, ArtifactSignatureSummary, ContentPreviewRequest,
    ContentPreviewResponse, ContentTarget, HexPreviewRow, PreviewChunkResponse, PreviewFact,
    PreviewSessionInfo, PreviewSessionOpenRequest, RecoveryPlan, ScanSource, SourceAccessState,
    SourceEntry,
};
use rss_windows::{RawReader, read_ntfs_record_range_for_source, read_source_range};
use std::{
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::PathBuf,
    process::Command,
};
use tar::Archive as TarArchive;
use zip::ZipArchive;

const DEFAULT_PREVIEW_WINDOW: u64 = 4096;
const MAX_PREVIEW_WINDOW: u64 = 64 * 1024;
const MAX_ARCHIVE_PREVIEW_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const MAX_ARCHIVE_SESSION_ENTRIES: usize = 65_536;

#[derive(Debug, Clone)]
pub struct PreviewArchiveListing {
    entries: Vec<ArchivePreviewEntry>,
    total_entries: Option<usize>,
    truncated: bool,
}

#[derive(Debug, Clone)]
pub struct PreparedPreviewSession {
    pub target_key: String,
    pub requested_mode: ArtifactPreviewMode,
    pub resolved_mode: ArtifactPreviewMode,
    pub total_size: u64,
    pub summary: Vec<PreviewFact>,
    pub warnings: Vec<String>,
    pub archive_listing: Option<PreviewArchiveListing>,
}

pub fn build_preview(
    artifact: &ArtifactRecord,
    request: &ArtifactPreviewRequest,
) -> Result<ArtifactPreviewResponse> {
    let requested_mode = request.mode;
    let requested_offset = request.offset.unwrap_or(0);
    let requested_length = request
        .length
        .unwrap_or(DEFAULT_PREVIEW_WINDOW)
        .clamp(256, MAX_PREVIEW_WINDOW);
    let total_size = artifact.size;
    let offset = requested_offset.min(total_size);
    let length = requested_length.min(total_size.saturating_sub(offset));
    let mut warnings = Vec::new();
    let summary = artifact.preview.clone();

    let resolved_mode = match requested_mode {
        ArtifactPreviewMode::Auto => preferred_preview_mode(artifact.kind),
        other => other,
    };

    match resolved_mode {
        ArtifactPreviewMode::Archive => {
            if requested_mode == ArtifactPreviewMode::Auto && total_size > MAX_ARCHIVE_PREVIEW_BYTES
            {
                warnings.push(format!(
                    "Archive auto-preview is limited to {} bytes; falling back to hex view.",
                    MAX_ARCHIVE_PREVIEW_BYTES
                ));
                return fallback_hex_preview(
                    artifact,
                    requested_mode,
                    offset,
                    length,
                    total_size,
                    warnings,
                    summary,
                );
            }
            let max_entries = request
                .max_entries
                .unwrap_or(MAX_ARCHIVE_ENTRIES)
                .clamp(1, MAX_ARCHIVE_ENTRIES);
            match build_archive_preview(artifact, max_entries, &mut warnings) {
                Ok(archive_listing) if !archive_listing.entries.is_empty() => {
                    if archive_listing.truncated {
                        warnings.push(match archive_listing.total_entries {
                            Some(total_entries) => format!(
                                "Showing the first {} of {total_entries} archive entries.",
                                archive_listing.entries.len()
                            ),
                            None => format!(
                                "Showing the first {} recovered archive entries.",
                                archive_listing.entries.len()
                            ),
                        });
                    }
                    Ok(ArtifactPreviewResponse {
                        artifact_id: artifact.id.clone(),
                        requested_mode,
                        resolved_mode,
                        offset: 0,
                        length: total_size.min(MAX_ARCHIVE_PREVIEW_BYTES),
                        total_size,
                        has_more: false,
                        warnings,
                        summary,
                        text_excerpt: None,
                        hex_rows: Vec::new(),
                        archive_entry_count: archive_listing.total_entries,
                        archive_entries_truncated: archive_listing.truncated,
                        archive_entries: archive_listing.entries,
                    })
                }
                Ok(_) => fallback_hex_preview(
                    artifact,
                    requested_mode,
                    offset,
                    length,
                    total_size,
                    warnings,
                    summary,
                ),
                Err(error) => {
                    warnings.push(error.to_string());
                    fallback_hex_preview(
                        artifact,
                        requested_mode,
                        offset,
                        length,
                        total_size,
                        warnings,
                        summary,
                    )
                }
            }
        }
        ArtifactPreviewMode::Text => {
            let bytes = read_artifact_range(artifact, offset, length)?;
            if let Some(text) = decode_text_excerpt(&bytes) {
                Ok(ArtifactPreviewResponse {
                    artifact_id: artifact.id.clone(),
                    requested_mode,
                    resolved_mode,
                    offset,
                    length: bytes.len() as u64,
                    total_size,
                    has_more: offset.saturating_add(bytes.len() as u64) < total_size,
                    warnings,
                    summary,
                    text_excerpt: Some(text),
                    hex_rows: Vec::new(),
                    archive_entry_count: None,
                    archive_entries_truncated: false,
                    archive_entries: Vec::new(),
                })
            } else {
                warnings.push(
                    "Text decoding confidence was too low; falling back to hex view.".to_string(),
                );
                fallback_hex_preview(
                    artifact,
                    requested_mode,
                    offset,
                    length,
                    total_size,
                    warnings,
                    summary,
                )
            }
        }
        ArtifactPreviewMode::Hex => fallback_hex_preview(
            artifact,
            requested_mode,
            offset,
            length,
            total_size,
            warnings,
            summary,
        ),
        ArtifactPreviewMode::Auto => unreachable!(),
    }
}

pub fn build_entry_preview(
    source: &ScanSource,
    entry: &SourceEntry,
    request: &ContentPreviewRequest,
) -> Result<ContentPreviewResponse> {
    if entry.is_directory {
        return Ok(ContentPreviewResponse {
            target_key: entry.path.clone(),
            requested_mode: request.mode,
            resolved_mode: ArtifactPreviewMode::Hex,
            offset: 0,
            length: 0,
            total_size: 0,
            has_more: false,
            warnings: vec!["Directories do not expose a byte preview.".to_string()],
            summary: source_entry_summary(entry),
            text_excerpt: None,
            hex_rows: Vec::new(),
            archive_entry_count: None,
            archive_entries_truncated: false,
            archive_entries: Vec::new(),
        });
    }

    let requested_mode = request.mode;
    let requested_offset = request.offset.unwrap_or(0);
    let requested_length = request
        .length
        .unwrap_or(DEFAULT_PREVIEW_WINDOW)
        .clamp(256, MAX_PREVIEW_WINDOW);
    let total_size = entry.size;
    let offset = requested_offset.min(total_size);
    let length = requested_length.min(total_size.saturating_sub(offset));
    let mut warnings = Vec::new();
    let summary = source_entry_summary(entry);
    let kind = if entry.is_directory {
        ArtifactKind::Unknown
    } else {
        rss_core::infer_artifact_kind(&entry.name, None)
    };
    let resolved_mode = match requested_mode {
        ArtifactPreviewMode::Auto if entry.is_metafile => ArtifactPreviewMode::Hex,
        ArtifactPreviewMode::Auto if should_force_chunked_hex_preview(entry) => {
            warnings.push(format!(
                "Large or protected live file {} defaults to chunked hex preview to avoid blocking the UI.",
                entry.path
            ));
            ArtifactPreviewMode::Hex
        }
        ArtifactPreviewMode::Auto => {
            let preferred = preferred_preview_mode(kind);
            if preferred == ArtifactPreviewMode::Archive {
                warnings.push(format!(
                    "Live archive auto-preview is deferred for {} to keep the UI responsive. Switch to Archive mode to enumerate entries.",
                    entry.path
                ));
                ArtifactPreviewMode::Hex
            } else {
                preferred
            }
        }
        other => other,
    };

    match resolved_mode {
        ArtifactPreviewMode::Archive => {
            if requested_mode == ArtifactPreviewMode::Auto
                && (entry.is_metafile || total_size > MAX_ARCHIVE_PREVIEW_BYTES)
            {
                warnings.push(if entry.is_metafile {
                    "Metadata objects default to hex preview to avoid blocking archive inspection."
                        .to_string()
                } else {
                    format!(
                        "Archive auto-preview is limited to {} bytes; falling back to hex view.",
                        MAX_ARCHIVE_PREVIEW_BYTES
                    )
                });
                return fallback_entry_hex_preview(
                    source,
                    entry,
                    EntryHexPreviewContext {
                        requested_mode,
                        offset,
                        length,
                        total_size,
                        warnings,
                        summary,
                    },
                );
            }
            let max_entries = request
                .max_entries
                .unwrap_or(MAX_ARCHIVE_ENTRIES)
                .clamp(1, MAX_ARCHIVE_ENTRIES);
            match build_archive_preview_from_bytes(
                &entry.name,
                kind,
                total_size,
                &materialize_source_bytes(source, entry, MAX_ARCHIVE_PREVIEW_BYTES)?,
                max_entries,
                &mut warnings,
            ) {
                Ok(archive_listing) if !archive_listing.entries.is_empty() => {
                    if archive_listing.truncated {
                        warnings.push(match archive_listing.total_entries {
                            Some(total_entries) => format!(
                                "Showing the first {} of {total_entries} archive entries.",
                                archive_listing.entries.len()
                            ),
                            None => format!(
                                "Showing the first {} recovered archive entries.",
                                archive_listing.entries.len()
                            ),
                        });
                    }
                    Ok(ContentPreviewResponse {
                        target_key: entry.path.clone(),
                        requested_mode,
                        resolved_mode,
                        offset: 0,
                        length: total_size.min(MAX_ARCHIVE_PREVIEW_BYTES),
                        total_size,
                        has_more: false,
                        warnings,
                        summary,
                        text_excerpt: None,
                        hex_rows: Vec::new(),
                        archive_entry_count: archive_listing.total_entries,
                        archive_entries_truncated: archive_listing.truncated,
                        archive_entries: archive_listing.entries,
                    })
                }
                Ok(_) => fallback_entry_hex_preview(
                    source,
                    entry,
                    EntryHexPreviewContext {
                        requested_mode,
                        offset,
                        length,
                        total_size,
                        warnings,
                        summary,
                    },
                ),
                Err(error) => {
                    warnings.push(error.to_string());
                    fallback_entry_hex_preview(
                        source,
                        entry,
                        EntryHexPreviewContext {
                            requested_mode,
                            offset,
                            length,
                            total_size,
                            warnings,
                            summary,
                        },
                    )
                }
            }
        }
        ArtifactPreviewMode::Text => {
            let bytes = match read_live_entry_range(source, entry, offset, length) {
                Ok(bytes) => bytes,
                Err(error) => {
                    warnings.push(describe_live_entry_read_error(entry, &error));
                    Vec::new()
                }
            };
            if bytes.is_empty() && !warnings.is_empty() {
                return Ok(ContentPreviewResponse {
                    target_key: entry.path.clone(),
                    requested_mode,
                    resolved_mode: ArtifactPreviewMode::Text,
                    offset,
                    length: 0,
                    total_size,
                    has_more: false,
                    warnings,
                    summary,
                    text_excerpt: Some(String::new()),
                    hex_rows: Vec::new(),
                    archive_entry_count: None,
                    archive_entries_truncated: false,
                    archive_entries: Vec::new(),
                });
            }
            if let Some(text) = decode_text_excerpt(&bytes) {
                Ok(ContentPreviewResponse {
                    target_key: entry.path.clone(),
                    requested_mode,
                    resolved_mode,
                    offset,
                    length: bytes.len() as u64,
                    total_size,
                    has_more: offset.saturating_add(bytes.len() as u64) < total_size,
                    warnings,
                    summary,
                    text_excerpt: Some(text),
                    hex_rows: Vec::new(),
                    archive_entry_count: None,
                    archive_entries_truncated: false,
                    archive_entries: Vec::new(),
                })
            } else {
                warnings.push(
                    "Text decoding confidence was too low; falling back to hex view.".to_string(),
                );
                fallback_entry_hex_preview(
                    source,
                    entry,
                    EntryHexPreviewContext {
                        requested_mode,
                        offset,
                        length,
                        total_size,
                        warnings,
                        summary,
                    },
                )
            }
        }
        ArtifactPreviewMode::Hex => match read_live_entry_range(source, entry, offset, length) {
            Ok(bytes) => Ok(ContentPreviewResponse {
                target_key: entry.path.clone(),
                requested_mode,
                resolved_mode: ArtifactPreviewMode::Hex,
                offset,
                length: bytes.len() as u64,
                total_size,
                has_more: offset.saturating_add(bytes.len() as u64) < total_size,
                warnings,
                summary,
                text_excerpt: None,
                hex_rows: build_hex_rows(offset, &bytes),
                archive_entry_count: None,
                archive_entries_truncated: false,
                archive_entries: Vec::new(),
            }),
            Err(error) => {
                warnings.push(describe_live_entry_read_error(entry, &error));
                Ok(empty_entry_preview_response(
                    entry,
                    requested_mode,
                    ArtifactPreviewMode::Hex,
                    total_size,
                    warnings,
                    summary,
                ))
            }
        },
        ArtifactPreviewMode::Auto => unreachable!(),
    }
}

pub fn open_preview_session_for_target(
    source_lookup: impl FnOnce(&str) -> Result<ScanSource>,
    entry_lookup: impl FnOnce(&ScanSource, &str) -> Result<SourceEntry>,
    artifact_lookup: impl FnOnce(&str, &str) -> Result<ArtifactRecord>,
    request: &PreviewSessionOpenRequest,
) -> Result<(PreparedPreviewSession, PreviewSessionTarget)> {
    match &request.target {
        ContentTarget::Artifact {
            scan_id,
            artifact_id,
        } => {
            let artifact = artifact_lookup(scan_id, artifact_id)?;
            let session = prepare_artifact_preview_session(&artifact, request.mode)?;
            Ok((session, PreviewSessionTarget::Artifact(artifact)))
        }
        ContentTarget::Entry { source_id, path } => {
            let source = source_lookup(source_id)?;
            let entry = if let Some(entry_hint) = request
                .entry_hint
                .clone()
                .filter(|entry| entry.path == *path)
            {
                entry_hint
            } else {
                entry_lookup(&source, path)?
            };
            let session = prepare_entry_preview_session(&source, &entry, request.mode)?;
            Ok((session, PreviewSessionTarget::Entry { source, entry }))
        }
    }
}

#[derive(Debug, Clone)]
pub enum PreviewSessionTarget {
    Artifact(ArtifactRecord),
    Entry {
        source: ScanSource,
        entry: SourceEntry,
    },
}

pub fn read_preview_chunk(
    session_id: &str,
    target: &PreviewSessionTarget,
    prepared: &PreparedPreviewSession,
    offset: u64,
    length: u64,
) -> Result<PreviewChunkResponse> {
    match target {
        PreviewSessionTarget::Artifact(artifact) => {
            read_artifact_preview_chunk(session_id, artifact, prepared, offset, length)
        }
        PreviewSessionTarget::Entry { source, entry } => {
            read_entry_preview_chunk(session_id, source, entry, prepared, offset, length)
        }
    }
}

pub fn read_archive_page(
    session_id: &str,
    target_key: &str,
    listing: &PreviewArchiveListing,
    offset: usize,
    limit: usize,
    warnings: &[String],
) -> ArchivePreviewPage {
    let safe_offset = offset.min(listing.entries.len());
    let safe_limit = limit.clamp(1, 2048);
    let end = safe_offset
        .saturating_add(safe_limit)
        .min(listing.entries.len());
    ArchivePreviewPage {
        session_id: session_id.to_string(),
        target_key: target_key.to_string(),
        offset: safe_offset,
        count: end.saturating_sub(safe_offset),
        total_entries: listing.total_entries,
        has_more: end < listing.entries.len()
            || listing
                .total_entries
                .is_some_and(|total_entries| end < total_entries),
        warnings: warnings.to_vec(),
        entries: listing.entries[safe_offset..end].to_vec(),
    }
}

pub fn session_info(session_id: &str, prepared: &PreparedPreviewSession) -> PreviewSessionInfo {
    PreviewSessionInfo {
        session_id: session_id.to_string(),
        target_key: prepared.target_key.clone(),
        requested_mode: prepared.requested_mode,
        resolved_mode: prepared.resolved_mode,
        total_size: prepared.total_size,
        summary: prepared.summary.clone(),
        warnings: prepared.warnings.clone(),
        preview_ready: prepared.resolved_mode != ArtifactPreviewMode::Archive
            || prepared.archive_listing.is_some(),
        archive_entry_count: prepared
            .archive_listing
            .as_ref()
            .and_then(|listing| listing.total_entries),
        archive_entries_truncated: prepared
            .archive_listing
            .as_ref()
            .is_some_and(|listing| listing.truncated),
    }
}

fn prepare_artifact_preview_session(
    artifact: &ArtifactRecord,
    requested_mode: ArtifactPreviewMode,
) -> Result<PreparedPreviewSession> {
    let mut warnings = Vec::new();
    let mut resolved_mode = match requested_mode {
        ArtifactPreviewMode::Auto => preferred_preview_mode(artifact.kind),
        other => other,
    };
    let archive_listing = if resolved_mode == ArtifactPreviewMode::Archive {
        if artifact.size > MAX_ARCHIVE_PREVIEW_BYTES {
            warnings.push(format!(
                "Archive preview is limited to {} bytes; using chunked hex view instead.",
                MAX_ARCHIVE_PREVIEW_BYTES
            ));
            resolved_mode = ArtifactPreviewMode::Hex;
            None
        } else {
            match build_archive_preview(artifact, MAX_ARCHIVE_SESSION_ENTRIES, &mut warnings) {
                Ok(listing) if !listing.entries.is_empty() => Some(listing),
                Ok(_) => {
                    warnings.push(
                        "Archive structure could not be reconstructed; using chunked hex view instead."
                            .to_string(),
                    );
                    resolved_mode = ArtifactPreviewMode::Hex;
                    None
                }
                Err(error) => {
                    warnings.push(format!(
                        "Archive preview unavailable: {error}. Using chunked hex view instead."
                    ));
                    resolved_mode = ArtifactPreviewMode::Hex;
                    None
                }
            }
        }
    } else {
        None
    };

    Ok(PreparedPreviewSession {
        target_key: format!("artifact:{}:{}", artifact.scan_id, artifact.id),
        requested_mode,
        resolved_mode,
        total_size: artifact.size,
        summary: artifact.preview.clone(),
        warnings,
        archive_listing,
    })
}

fn prepare_entry_preview_session(
    source: &ScanSource,
    entry: &SourceEntry,
    requested_mode: ArtifactPreviewMode,
) -> Result<PreparedPreviewSession> {
    let mut warnings = Vec::new();
    let kind = if entry.is_directory {
        ArtifactKind::Unknown
    } else {
        rss_core::infer_artifact_kind(&entry.name, None)
    };
    let mut resolved_mode = match requested_mode {
        ArtifactPreviewMode::Auto if entry.is_directory => ArtifactPreviewMode::Hex,
        ArtifactPreviewMode::Auto if entry.is_metafile => ArtifactPreviewMode::Hex,
        ArtifactPreviewMode::Auto if should_force_chunked_hex_preview(entry) => {
            warnings.push(format!(
                "Large or protected live file {} defaults to chunked hex preview to avoid blocking the UI.",
                entry.path
            ));
            ArtifactPreviewMode::Hex
        }
        ArtifactPreviewMode::Auto => {
            let preferred = preferred_preview_mode(kind);
            if preferred == ArtifactPreviewMode::Archive {
                warnings.push(format!(
                    "Live archive auto-preview is deferred for {} to keep the UI responsive. Switch to Archive mode to enumerate entries.",
                    entry.path
                ));
                ArtifactPreviewMode::Hex
            } else {
                preferred
            }
        }
        other => other,
    };
    let archive_listing = if resolved_mode == ArtifactPreviewMode::Archive {
        if entry.size > MAX_ARCHIVE_PREVIEW_BYTES {
            warnings.push(format!(
                "Archive preview is limited to {} bytes; using chunked hex view instead.",
                MAX_ARCHIVE_PREVIEW_BYTES
            ));
            resolved_mode = ArtifactPreviewMode::Hex;
            None
        } else {
            match materialize_source_bytes(source, entry, MAX_ARCHIVE_PREVIEW_BYTES).and_then(
                |bytes| {
                    build_archive_preview_from_bytes(
                        &entry.name,
                        kind,
                        entry.size,
                        &bytes,
                        MAX_ARCHIVE_SESSION_ENTRIES,
                        &mut warnings,
                    )
                },
            ) {
                Ok(listing) if !listing.entries.is_empty() => Some(listing),
                Ok(_) => {
                    warnings.push(
                        "Archive structure could not be reconstructed; using chunked hex view instead."
                            .to_string(),
                    );
                    resolved_mode = ArtifactPreviewMode::Hex;
                    None
                }
                Err(error) => {
                    warnings.push(format!(
                        "Archive preview unavailable: {error}. Using chunked hex view instead."
                    ));
                    resolved_mode = ArtifactPreviewMode::Hex;
                    None
                }
            }
        }
    } else {
        None
    };

    Ok(PreparedPreviewSession {
        target_key: format!("entry:{}:{}", source.id, entry.path),
        requested_mode,
        resolved_mode,
        total_size: entry.size,
        summary: source_entry_summary(entry),
        warnings,
        archive_listing,
    })
}

fn read_artifact_preview_chunk(
    session_id: &str,
    artifact: &ArtifactRecord,
    prepared: &PreparedPreviewSession,
    offset: u64,
    length: u64,
) -> Result<PreviewChunkResponse> {
    let safe_length = length.clamp(256, MAX_PREVIEW_WINDOW);
    let total_size = prepared.total_size;
    let safe_offset = offset.min(total_size);
    let read_length = safe_length.min(total_size.saturating_sub(safe_offset));

    match prepared.resolved_mode {
        ArtifactPreviewMode::Text => {
            let bytes = read_artifact_range(artifact, safe_offset, read_length)?;
            let text_excerpt = decode_text_excerpt(&bytes)
                .or_else(|| Some(String::from_utf8_lossy(&bytes).to_string()));
            Ok(PreviewChunkResponse {
                session_id: session_id.to_string(),
                target_key: prepared.target_key.clone(),
                requested_mode: prepared.requested_mode,
                resolved_mode: prepared.resolved_mode,
                offset: safe_offset,
                length: bytes.len() as u64,
                total_size,
                has_more: safe_offset.saturating_add(bytes.len() as u64) < total_size,
                warnings: prepared.warnings.clone(),
                text_excerpt,
                hex_rows: Vec::new(),
            })
        }
        ArtifactPreviewMode::Hex | ArtifactPreviewMode::Auto => {
            let bytes = read_artifact_range(artifact, safe_offset, read_length)?;
            Ok(PreviewChunkResponse {
                session_id: session_id.to_string(),
                target_key: prepared.target_key.clone(),
                requested_mode: prepared.requested_mode,
                resolved_mode: ArtifactPreviewMode::Hex,
                offset: safe_offset,
                length: bytes.len() as u64,
                total_size,
                has_more: safe_offset.saturating_add(bytes.len() as u64) < total_size,
                warnings: prepared.warnings.clone(),
                text_excerpt: None,
                hex_rows: build_hex_rows(safe_offset, &bytes),
            })
        }
        ArtifactPreviewMode::Archive => Ok(PreviewChunkResponse {
            session_id: session_id.to_string(),
            target_key: prepared.target_key.clone(),
            requested_mode: prepared.requested_mode,
            resolved_mode: ArtifactPreviewMode::Archive,
            offset: 0,
            length: 0,
            total_size,
            has_more: false,
            warnings: prepared.warnings.clone(),
            text_excerpt: None,
            hex_rows: Vec::new(),
        }),
    }
}

fn read_entry_preview_chunk(
    session_id: &str,
    source: &ScanSource,
    entry: &SourceEntry,
    prepared: &PreparedPreviewSession,
    offset: u64,
    length: u64,
) -> Result<PreviewChunkResponse> {
    let safe_length = length.clamp(256, MAX_PREVIEW_WINDOW);
    let total_size = prepared.total_size;
    let safe_offset = offset.min(total_size);
    let read_length = safe_length.min(total_size.saturating_sub(safe_offset));

    if should_skip_live_byte_preview(entry) {
        return Ok(unavailable_entry_preview_chunk(
            session_id,
            prepared,
            safe_offset,
            total_size,
            match prepared.resolved_mode {
                ArtifactPreviewMode::Text => ArtifactPreviewMode::Text,
                _ => ArtifactPreviewMode::Hex,
            },
            describe_live_entry_open_failure(entry),
        ));
    }

    match prepared.resolved_mode {
        ArtifactPreviewMode::Text => {
            let bytes = match read_live_entry_range(source, entry, safe_offset, read_length) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Ok(unavailable_entry_preview_chunk(
                        session_id,
                        prepared,
                        safe_offset,
                        total_size,
                        ArtifactPreviewMode::Text,
                        describe_live_entry_read_error(entry, &error),
                    ));
                }
            };
            let text_excerpt = decode_text_excerpt(&bytes)
                .or_else(|| Some(String::from_utf8_lossy(&bytes).to_string()));
            Ok(PreviewChunkResponse {
                session_id: session_id.to_string(),
                target_key: prepared.target_key.clone(),
                requested_mode: prepared.requested_mode,
                resolved_mode: prepared.resolved_mode,
                offset: safe_offset,
                length: bytes.len() as u64,
                total_size,
                has_more: safe_offset.saturating_add(bytes.len() as u64) < total_size,
                warnings: prepared.warnings.clone(),
                text_excerpt,
                hex_rows: Vec::new(),
            })
        }
        ArtifactPreviewMode::Hex | ArtifactPreviewMode::Auto => {
            let bytes = match read_live_entry_range(source, entry, safe_offset, read_length) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Ok(unavailable_entry_preview_chunk(
                        session_id,
                        prepared,
                        safe_offset,
                        total_size,
                        ArtifactPreviewMode::Hex,
                        describe_live_entry_read_error(entry, &error),
                    ));
                }
            };
            Ok(PreviewChunkResponse {
                session_id: session_id.to_string(),
                target_key: prepared.target_key.clone(),
                requested_mode: prepared.requested_mode,
                resolved_mode: ArtifactPreviewMode::Hex,
                offset: safe_offset,
                length: bytes.len() as u64,
                total_size,
                has_more: safe_offset.saturating_add(bytes.len() as u64) < total_size,
                warnings: prepared.warnings.clone(),
                text_excerpt: None,
                hex_rows: build_hex_rows(safe_offset, &bytes),
            })
        }
        ArtifactPreviewMode::Archive => Ok(PreviewChunkResponse {
            session_id: session_id.to_string(),
            target_key: prepared.target_key.clone(),
            requested_mode: prepared.requested_mode,
            resolved_mode: ArtifactPreviewMode::Archive,
            offset: 0,
            length: 0,
            total_size,
            has_more: false,
            warnings: prepared.warnings.clone(),
            text_excerpt: None,
            hex_rows: Vec::new(),
        }),
    }
}

pub fn inspect_signature(artifact: &ArtifactRecord) -> Result<ArtifactSignatureSummary> {
    if !matches!(
        artifact.kind,
        ArtifactKind::Exe
            | ArtifactKind::Dll
            | ArtifactKind::Sys
            | ArtifactKind::Scr
            | ArtifactKind::Ocx
            | ArtifactKind::Cpl
            | ArtifactKind::Pe
            | ArtifactKind::Msi
    ) {
        return Ok(ArtifactSignatureSummary {
            status: ArtifactSignatureStatus::NotApplicable,
            subject: None,
            issuer: None,
            timestamp: None,
            verification_source: "n/a".to_string(),
            note: Some(
                "Authenticode verification applies only to PE-family binaries and MSI packages."
                    .to_string(),
            ),
        });
    }

    let materialized = materialize_artifact_to_temp(artifact, 512 * 1024 * 1024)?;
    inspect_signature_from_path(&materialized.path)
}

pub fn inspect_entry_signature(
    source: &ScanSource,
    entry: &SourceEntry,
) -> Result<ArtifactSignatureSummary> {
    if should_skip_live_signature_inspection(entry) {
        return Ok(ArtifactSignatureSummary {
            status: ArtifactSignatureStatus::Indeterminate,
            subject: None,
            issuer: None,
            timestamp: None,
            verification_source: "policy:live-system-file".to_string(),
            note: Some(format!(
                "Signature verification is skipped for protected live system file {} to avoid blocking the UI.",
                entry.path
            )),
        });
    }

    let kind = rss_core::infer_artifact_kind(&entry.name, None);
    if !matches!(
        kind,
        ArtifactKind::Exe
            | ArtifactKind::Dll
            | ArtifactKind::Sys
            | ArtifactKind::Scr
            | ArtifactKind::Ocx
            | ArtifactKind::Cpl
            | ArtifactKind::Pe
            | ArtifactKind::Msi
    ) {
        return Ok(ArtifactSignatureSummary {
            status: ArtifactSignatureStatus::NotApplicable,
            subject: None,
            issuer: None,
            timestamp: None,
            verification_source: "n/a".to_string(),
            note: Some(
                "Authenticode verification applies only to PE-family binaries and MSI packages."
                    .to_string(),
            ),
        });
    }

    let direct_path = PathBuf::from(&entry.path);
    if direct_path.exists() {
        return inspect_signature_from_path(&direct_path);
    }

    let materialized = materialize_source_to_temp(source, entry, 512 * 1024 * 1024)?;
    inspect_signature_from_path(&materialized.path)
}

fn inspect_signature_from_path(path: &std::path::Path) -> Result<ArtifactSignatureSummary> {
    let escaped_path = path.display().to_string().replace('\'', "''");
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
try {{
$signature = Get-AuthenticodeSignature -LiteralPath '{escaped_path}'
[pscustomobject]@{{
  Status = [string]$signature.Status
  StatusMessage = $signature.StatusMessage
  Subject = if ($signature.SignerCertificate) {{ $signature.SignerCertificate.Subject }} else {{ $null }}
  Issuer = if ($signature.SignerCertificate) {{ $signature.SignerCertificate.Issuer }} else {{ $null }}
  Timestamp = $null
}} | ConvertTo-Json -Compress
}} catch {{
[pscustomobject]@{{
  Status = 'UnknownError'
  StatusMessage = $_.Exception.Message
  Subject = $null
  Issuer = $null
  Timestamp = $null
}} | ConvertTo-Json -Compress
}}"#
    );
    let encoded_command = BASE64.encode(
        script
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<u8>>(),
    );

    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded_command,
        ])
        .output()
        .context("Failed to launch PowerShell for Authenticode verification")?;

    if !output.status.success() {
        return Ok(ArtifactSignatureSummary {
            status: ArtifactSignatureStatus::Indeterminate,
            subject: None,
            issuer: None,
            timestamp: None,
            verification_source: "powershell:get-authenticodesignature".to_string(),
            note: Some(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        });
    }

    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("PowerShell did not return valid JSON for Authenticode verification")?;
    let status_raw = payload
        .get("Status")
        .and_then(|value| value.as_str())
        .unwrap_or("UnknownError");
    let note = payload
        .get("StatusMessage")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string());

    Ok(ArtifactSignatureSummary {
        status: map_signature_status(status_raw),
        subject: payload
            .get("Subject")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
        issuer: payload
            .get("Issuer")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
        timestamp: payload
            .get("Timestamp")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
        verification_source: "powershell:get-authenticodesignature".to_string(),
        note,
    })
}

fn fallback_hex_preview(
    artifact: &ArtifactRecord,
    requested_mode: ArtifactPreviewMode,
    offset: u64,
    length: u64,
    total_size: u64,
    warnings: Vec<String>,
    summary: Vec<PreviewFact>,
) -> Result<ArtifactPreviewResponse> {
    let bytes = read_artifact_range(artifact, offset, length)?;
    Ok(ArtifactPreviewResponse {
        artifact_id: artifact.id.clone(),
        requested_mode,
        resolved_mode: ArtifactPreviewMode::Hex,
        offset,
        length: bytes.len() as u64,
        total_size,
        has_more: offset.saturating_add(bytes.len() as u64) < total_size,
        warnings,
        summary,
        text_excerpt: None,
        hex_rows: build_hex_rows(offset, &bytes),
        archive_entry_count: None,
        archive_entries_truncated: false,
        archive_entries: Vec::new(),
    })
}

struct EntryHexPreviewContext {
    requested_mode: ArtifactPreviewMode,
    offset: u64,
    length: u64,
    total_size: u64,
    warnings: Vec<String>,
    summary: Vec<PreviewFact>,
}

fn fallback_entry_hex_preview(
    source: &ScanSource,
    entry: &SourceEntry,
    context: EntryHexPreviewContext,
) -> Result<ContentPreviewResponse> {
    let bytes = read_live_entry_range(source, entry, context.offset, context.length)?;
    Ok(ContentPreviewResponse {
        target_key: entry.path.clone(),
        requested_mode: context.requested_mode,
        resolved_mode: ArtifactPreviewMode::Hex,
        offset: context.offset,
        length: bytes.len() as u64,
        total_size: context.total_size,
        has_more: context.offset.saturating_add(bytes.len() as u64) < context.total_size,
        warnings: context.warnings,
        summary: context.summary,
        text_excerpt: None,
        hex_rows: build_hex_rows(context.offset, &bytes),
        archive_entry_count: None,
        archive_entries_truncated: false,
        archive_entries: Vec::new(),
    })
}

fn preferred_preview_mode(kind: ArtifactKind) -> ArtifactPreviewMode {
    match kind {
        ArtifactKind::Txt
        | ArtifactKind::Log
        | ArtifactKind::Ini
        | ArtifactKind::Cfg
        | ArtifactKind::Json
        | ArtifactKind::Yml
        | ArtifactKind::Yaml
        | ArtifactKind::Bat
        | ArtifactKind::Cmd
        | ArtifactKind::Ps1
        | ArtifactKind::Vbs
        | ArtifactKind::Js => ArtifactPreviewMode::Text,
        ArtifactKind::Zip
        | ArtifactKind::Jar
        | ArtifactKind::Apk
        | ArtifactKind::Tar
        | ArtifactKind::Gzip
        | ArtifactKind::Bzip2
        | ArtifactKind::Xz
        | ArtifactKind::Msi
        | ArtifactKind::OleCompound
        | ArtifactKind::Rar
        | ArtifactKind::SevenZip
        | ArtifactKind::Cab
        | ArtifactKind::Iso => ArtifactPreviewMode::Archive,
        _ => ArtifactPreviewMode::Hex,
    }
}

fn build_archive_preview(
    artifact: &ArtifactRecord,
    max_entries: usize,
    warnings: &mut Vec<String>,
) -> Result<PreviewArchiveListing> {
    let bytes = materialize_artifact_bytes(artifact, MAX_ARCHIVE_PREVIEW_BYTES)?;
    build_archive_preview_from_bytes(
        &artifact.name,
        artifact.kind,
        artifact.size,
        &bytes,
        max_entries,
        warnings,
    )
}

fn build_archive_preview_from_bytes(
    target_name: &str,
    kind: ArtifactKind,
    total_size: u64,
    bytes: &[u8],
    max_entries: usize,
    warnings: &mut Vec<String>,
) -> Result<PreviewArchiveListing> {
    match kind {
        ArtifactKind::Zip | ArtifactKind::Jar | ArtifactKind::Apk => {
            if let Ok(entries) = list_zip_entries(bytes, max_entries) {
                return Ok(entries);
            }
            warnings.push(
                "ZIP central directory could not be parsed cleanly; using local-header salvage."
                    .to_string(),
            );
            salvage_zip_local_headers(bytes, max_entries)
        }
        ArtifactKind::Msi | ArtifactKind::OleCompound => list_cfb_entries(bytes, max_entries),
        ArtifactKind::Tar => list_tar_entries(bytes, max_entries),
        ArtifactKind::Cab | ArtifactKind::Rar | ArtifactKind::SevenZip | ArtifactKind::Iso => {
            Ok(build_archive_summary_listing(
                target_name,
                kind,
                total_size,
                "Structured entry listing is not yet available for this archive family; header-aware summary only.",
            ))
        }
        ArtifactKind::Gzip | ArtifactKind::Bzip2 | ArtifactKind::Xz => {
            Ok(build_archive_summary_listing(
                target_name,
                kind,
                total_size,
                "Single-stream compressed payload detected; member listing is not yet available for this compression family.",
            ))
        }
        _ => Err(anyhow!(
            "Archive preview is not available for {}",
            kind.kind_name()
        )),
    }
}

fn build_archive_summary_listing(
    target_name: &str,
    kind: ArtifactKind,
    total_size: u64,
    note: &str,
) -> PreviewArchiveListing {
    PreviewArchiveListing {
        entries: vec![ArchivePreviewEntry {
            path: target_name.to_string(),
            kind: Some(kind.kind_name()),
            size: Some(total_size),
            compressed_size: None,
            status: ArchivePreviewEntryStatus::Unsupported,
            note: Some(note.to_string()),
        }],
        total_entries: Some(1),
        truncated: false,
    }
}

fn list_zip_entries(bytes: &[u8], max_entries: usize) -> Result<PreviewArchiveListing> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).context("ZIP central directory could not be parsed")?;
    let mut entries = Vec::new();
    let total_entries = archive.len();
    let count = total_entries.min(max_entries);
    for index in 0..count {
        let file = archive
            .by_index(index)
            .with_context(|| format!("Failed to inspect ZIP entry {index}"))?;
        entries.push(ArchivePreviewEntry {
            path: file.name().to_string(),
            kind: Some(if file.is_dir() { "directory" } else { "file" }.to_string()),
            size: Some(file.size()),
            compressed_size: Some(file.compressed_size()),
            status: ArchivePreviewEntryStatus::Ok,
            note: None,
        });
    }
    Ok(PreviewArchiveListing {
        truncated: total_entries > entries.len(),
        total_entries: Some(total_entries),
        entries,
    })
}

fn list_tar_entries(bytes: &[u8], max_entries: usize) -> Result<PreviewArchiveListing> {
    let mut archive = TarArchive::new(Cursor::new(bytes));
    let entries_iter = archive
        .entries()
        .context("TAR headers could not be parsed cleanly")?;
    let mut entries = Vec::new();
    let mut total_entries = 0usize;

    for entry_result in entries_iter {
        let entry = entry_result.context("Failed to inspect TAR entry")?;
        total_entries = total_entries.saturating_add(1);
        if entries.len() >= max_entries {
            continue;
        }
        let path = entry
            .path()
            .ok()
            .map(|path| path.to_string_lossy().to_string())
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| format!("entry-{total_entries}"));
        let kind = Some(
            if entry.header().entry_type().is_dir() {
                "directory"
            } else {
                "file"
            }
            .to_string(),
        );
        entries.push(ArchivePreviewEntry {
            path,
            kind,
            size: Some(entry.size()),
            compressed_size: None,
            status: ArchivePreviewEntryStatus::Ok,
            note: None,
        });
    }

    Ok(PreviewArchiveListing {
        truncated: total_entries > entries.len(),
        total_entries: Some(total_entries),
        entries,
    })
}

fn salvage_zip_local_headers(bytes: &[u8], max_entries: usize) -> Result<PreviewArchiveListing> {
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    let mut truncated = false;
    while cursor + 30 <= bytes.len() && entries.len() < max_entries {
        if &bytes[cursor..cursor + 4] != b"PK\x03\x04" {
            cursor += 1;
            continue;
        }

        let name_length = u16::from_le_bytes([bytes[cursor + 26], bytes[cursor + 27]]) as usize;
        let extra_length = u16::from_le_bytes([bytes[cursor + 28], bytes[cursor + 29]]) as usize;
        let header_end = cursor + 30 + name_length + extra_length;
        if header_end > bytes.len() {
            break;
        }

        let name_bytes = &bytes[cursor + 30..cursor + 30 + name_length];
        let name = String::from_utf8_lossy(name_bytes).to_string();
        if !name.is_empty() {
            let compressed_size = u32::from_le_bytes([
                bytes[cursor + 18],
                bytes[cursor + 19],
                bytes[cursor + 20],
                bytes[cursor + 21],
            ]) as u64;
            let size = u32::from_le_bytes([
                bytes[cursor + 22],
                bytes[cursor + 23],
                bytes[cursor + 24],
                bytes[cursor + 25],
            ]) as u64;
            let uses_data_descriptor = bytes[cursor + 6] & 0x08 != 0;
            entries.push(ArchivePreviewEntry {
                path: name,
                kind: Some("file".to_string()),
                size: Some(size).filter(|value| *value > 0),
                compressed_size: Some(compressed_size).filter(|value| *value > 0),
                status: if uses_data_descriptor {
                    ArchivePreviewEntryStatus::Partial
                } else {
                    ArchivePreviewEntryStatus::Damaged
                },
                note: Some(
                    "Recovered from a local ZIP header without a trusted central directory."
                        .to_string(),
                ),
            });
        }

        cursor = header_end;
    }

    if entries.len() >= max_entries && cursor + 30 <= bytes.len() {
        truncated = true;
    }

    if entries.is_empty() {
        Err(anyhow!("No salvageable ZIP local headers were found"))
    } else {
        Ok(PreviewArchiveListing {
            total_entries: None,
            truncated,
            entries,
        })
    }
}

fn list_cfb_entries(bytes: &[u8], max_entries: usize) -> Result<PreviewArchiveListing> {
    let compound = CompoundFile::open(Cursor::new(bytes))
        .context("Compound-file directory could not be parsed")?;
    let mut entries = Vec::new();
    let mut total_entries = 0usize;
    for entry in compound.walk().skip(1) {
        total_entries += 1;
        if entries.len() >= max_entries {
            continue;
        }
        entries.push(ArchivePreviewEntry {
            path: entry.path().display().to_string(),
            kind: Some(
                if entry.is_storage() {
                    "storage"
                } else {
                    "stream"
                }
                .to_string(),
            ),
            size: entry.is_stream().then_some(entry.len()),
            compressed_size: None,
            status: ArchivePreviewEntryStatus::Ok,
            note: None,
        });
    }
    Ok(PreviewArchiveListing {
        truncated: total_entries > entries.len(),
        total_entries: Some(total_entries),
        entries,
    })
}

fn materialize_artifact_bytes(artifact: &ArtifactRecord, limit: u64) -> Result<Vec<u8>> {
    if artifact.size > limit {
        return Err(anyhow!(
            "Artifact is {} bytes, which exceeds the preview budget of {} bytes",
            artifact.size,
            limit
        ));
    }
    read_artifact_range(artifact, 0, artifact.size)
}

fn materialize_source_bytes(
    source: &ScanSource,
    entry: &SourceEntry,
    limit: u64,
) -> Result<Vec<u8>> {
    if entry.size > limit {
        return Err(anyhow!(
            "Item is {} bytes, which exceeds the preview budget of {} bytes",
            entry.size,
            limit
        ));
    }

    read_live_entry_range(source, entry, 0, entry.size)
}

fn read_live_entry_range(
    source: &ScanSource,
    entry: &SourceEntry,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    if should_skip_live_byte_preview(entry) {
        return Err(anyhow!(describe_live_entry_open_failure(entry)));
    }

    let prefer_ntfs = should_prefer_ntfs_record_read(source, entry);
    let mut raw_error = None;

    if prefer_ntfs
        && let Some(record) = entry.mft_reference
        && let Ok(bytes) = read_ntfs_record_range_for_source(source, record, offset, length)
    {
        return Ok(bytes);
    } else if prefer_ntfs && entry.mft_reference.is_some() {
        raw_error = entry.mft_reference.and_then(|record| {
            read_ntfs_record_range_for_source(source, record, offset, length).err()
        });
    }

    if !matches!(entry.access_state, SourceAccessState::Denied)
        && let Ok(bytes) = read_source_range(source, &entry.path, offset, length)
    {
        return Ok(bytes);
    }

    if let Some(record) = entry.mft_reference
        && source.filesystem == rss_core::FileSystemKind::Ntfs
        && let Ok(bytes) = read_ntfs_record_range_for_source(source, record, offset, length)
    {
        return Ok(bytes);
    }

    if let Some(error) = raw_error {
        return Err(error.context(format!("Unable to preview {}", entry.path)));
    }

    Err(anyhow!(describe_live_entry_open_failure(entry)))
}

fn read_artifact_range(artifact: &ArtifactRecord, offset: u64, length: u64) -> Result<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }

    match &artifact.recovery_plan {
        RecoveryPlan::ResidentBase64 {
            base64,
            logical_size,
        } => {
            let bytes = BASE64
                .decode(base64)
                .context("Resident preview data could not be decoded")?;
            let start = offset.min(*logical_size) as usize;
            let end = offset.saturating_add(length).min(*logical_size) as usize;
            Ok(bytes.get(start..end).unwrap_or(&[]).to_vec())
        }
        RecoveryPlan::RawRuns {
            source_path,
            runs,
            logical_size,
        } => {
            let end_offset = offset.saturating_add(length).min(*logical_size);
            if end_offset <= offset {
                return Ok(Vec::new());
            }

            let mut source = RawReader::open(source_path)?;
            let mut output = Vec::with_capacity((end_offset - offset) as usize);
            let mut logical_cursor = 0u64;

            for run in runs {
                let run_end = logical_cursor.saturating_add(run.length);
                if run_end <= offset {
                    logical_cursor = run_end;
                    continue;
                }
                if logical_cursor >= end_offset {
                    break;
                }

                let slice_start = offset.saturating_sub(logical_cursor);
                let slice_end = (end_offset - logical_cursor).min(run.length);
                let to_read = slice_end.saturating_sub(slice_start);
                if to_read == 0 {
                    logical_cursor = run_end;
                    continue;
                }

                if run.sparse {
                    output.extend(std::iter::repeat_n(0u8, to_read as usize));
                } else {
                    match source.read_at(run.offset.saturating_add(slice_start), to_read as usize) {
                        Ok(buffer) => output.extend_from_slice(&buffer),
                        Err(error) if output.is_empty() => {
                            return Err(error.context(format!(
                                "Failed to read {to_read} preview bytes from {}",
                                source_path
                            )));
                        }
                        Err(_) => break,
                    }
                }

                logical_cursor = run_end;
            }

            Ok(output)
        }
        RecoveryPlan::Unrecoverable { reason } => Err(anyhow!(reason.clone())),
    }
}

fn build_hex_rows(base_offset: u64, bytes: &[u8]) -> Vec<HexPreviewRow> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(index, chunk)| HexPreviewRow {
            offset: base_offset + (index as u64 * 16),
            hex: chunk
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
            ascii: chunk
                .iter()
                .map(|byte| {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect(),
        })
        .collect()
}

fn decode_text_excerpt(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    let mut detector = EncodingDetector::new();
    detector.feed(bytes, true);
    let (encoding, confident) = detector.guess_assess(None, true);
    let nul_ratio =
        bytes.iter().filter(|byte| **byte == 0).count() as f32 / bytes.len().max(1) as f32;
    let encoding_name = encoding.name();
    let utf16_like = matches!(encoding_name, "UTF-16LE" | "UTF-16BE");
    if nul_ratio >= 0.08 && !utf16_like {
        return None;
    }
    let mut reader = DecodeReaderBytesBuilder::new()
        .encoding(Some(encoding))
        .build(bytes);
    let mut decoded = String::new();
    reader.read_to_string(&mut decoded).ok()?;

    let replacement_ratio = decoded.chars().filter(|ch| *ch == '\u{fffd}').count() as f32
        / decoded.chars().count().max(1) as f32;
    let printable_ratio = decoded
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\r' | '\n' | '\t'))
        .count() as f32
        / decoded.chars().count().max(1) as f32;
    if replacement_ratio > 0.02 {
        return None;
    }
    if confident || printable_ratio >= 0.9 {
        Some(decoded)
    } else {
        None
    }
}

fn map_signature_status(status: &str) -> ArtifactSignatureStatus {
    match status {
        "Valid" => ArtifactSignatureStatus::Valid,
        "NotSigned" => ArtifactSignatureStatus::None,
        "HashMismatch" | "NotTrusted" | "UnknownError" => ArtifactSignatureStatus::Invalid,
        "NotSupportedFileFormat" => ArtifactSignatureStatus::NotApplicable,
        _ => ArtifactSignatureStatus::Indeterminate,
    }
}

struct MaterializedArtifact {
    path: PathBuf,
}

impl Drop for MaterializedArtifact {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn materialize_artifact_to_temp(
    artifact: &ArtifactRecord,
    limit: u64,
) -> Result<MaterializedArtifact> {
    if artifact.size > limit {
        return Err(anyhow!(
            "Artifact is {} bytes, which exceeds the signature-verification budget of {} bytes",
            artifact.size,
            limit
        ));
    }

    let bytes = materialize_artifact_bytes(artifact, limit)?;
    let temp_dir = std::env::temp_dir().join("files");
    fs::create_dir_all(&temp_dir)
        .with_context(|| format!("Failed to create {}", temp_dir.display()))?;
    let temp_path = temp_dir.join(format!(
        "{}_{}",
        artifact.id,
        sanitize_temp_name(&artifact.name)
    ));
    let mut file = File::create(&temp_path)
        .with_context(|| format!("Failed to create {}", temp_path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("Failed to write {}", temp_path.display()))?;
    Ok(MaterializedArtifact { path: temp_path })
}

fn materialize_source_to_temp(
    source: &ScanSource,
    entry: &SourceEntry,
    limit: u64,
) -> Result<MaterializedArtifact> {
    let bytes = materialize_source_bytes(source, entry, limit)?;
    let temp_dir = std::env::temp_dir().join("files");
    fs::create_dir_all(&temp_dir)
        .with_context(|| format!("Failed to create {}", temp_dir.display()))?;
    let temp_path = temp_dir.join(format!(
        "entry_{}_{}",
        sanitize_temp_name(&entry.name),
        entry
            .mft_reference
            .map(|value| value.to_string())
            .unwrap_or_else(|| "path".to_string())
    ));
    let mut file = File::create(&temp_path)
        .with_context(|| format!("Failed to create {}", temp_path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("Failed to write {}", temp_path.display()))?;
    Ok(MaterializedArtifact { path: temp_path })
}

fn unavailable_entry_preview_chunk(
    session_id: &str,
    prepared: &PreparedPreviewSession,
    offset: u64,
    total_size: u64,
    resolved_mode: ArtifactPreviewMode,
    warning: String,
) -> PreviewChunkResponse {
    let mut warnings = prepared.warnings.clone();
    if !warnings.iter().any(|existing| existing == &warning) {
        warnings.push(warning);
    }
    PreviewChunkResponse {
        session_id: session_id.to_string(),
        target_key: prepared.target_key.clone(),
        requested_mode: prepared.requested_mode,
        resolved_mode,
        offset,
        length: 0,
        total_size,
        has_more: false,
        warnings,
        text_excerpt: if resolved_mode == ArtifactPreviewMode::Text {
            Some(String::new())
        } else {
            None
        },
        hex_rows: Vec::new(),
    }
}

fn empty_entry_preview_response(
    entry: &SourceEntry,
    requested_mode: ArtifactPreviewMode,
    resolved_mode: ArtifactPreviewMode,
    total_size: u64,
    warnings: Vec<String>,
    summary: Vec<PreviewFact>,
) -> ContentPreviewResponse {
    ContentPreviewResponse {
        target_key: entry.path.clone(),
        requested_mode,
        resolved_mode,
        offset: 0,
        length: 0,
        total_size,
        has_more: false,
        warnings,
        summary,
        text_excerpt: None,
        hex_rows: Vec::new(),
        archive_entry_count: None,
        archive_entries_truncated: false,
        archive_entries: Vec::new(),
    }
}

fn should_prefer_ntfs_record_read(source: &ScanSource, entry: &SourceEntry) -> bool {
    source.filesystem == rss_core::FileSystemKind::Ntfs
        && entry.mft_reference.is_some()
        && (matches!(entry.access_state, SourceAccessState::Denied)
            || entry.system
            || matches!(
                entry.extension.as_deref().map(|value| value.to_ascii_lowercase()),
                Some(extension)
                    if matches!(
                        extension.as_str(),
                        "sys" | "dll" | "exe" | "mui" | "cat" | "ocx" | "cpl"
                    )
            ))
}

fn should_force_chunked_hex_preview(entry: &SourceEntry) -> bool {
    is_virtual_memory_backed_system_file(entry)
        || entry.size >= 4 * 1024 * 1024 * 1024
        || matches!(entry.access_state, SourceAccessState::Denied)
}

fn should_skip_live_byte_preview(entry: &SourceEntry) -> bool {
    is_virtual_memory_backed_system_file(entry)
        || matches!(entry.access_state, SourceAccessState::Denied)
}

fn should_skip_live_signature_inspection(entry: &SourceEntry) -> bool {
    should_skip_live_byte_preview(entry)
}

fn is_virtual_memory_backed_system_file(entry: &SourceEntry) -> bool {
    let name = entry.name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "swapfile.sys" | "pagefile.sys" | "hiberfil.sys"
    )
}

fn describe_live_entry_open_failure(entry: &SourceEntry) -> String {
    if matches!(entry.access_state, SourceAccessState::Denied) {
        return format!(
            "Access denied for {}. Preview bytes are unavailable for this live file.",
            entry.path
        );
    }
    if is_virtual_memory_backed_system_file(entry) {
        return format!(
            "Protected virtual-memory file {} is not previewed directly. Showing metadata only.",
            entry.path
        );
    }
    if entry
        .extension
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("sys"))
        || entry.system
    {
        return format!(
            "Live system file {} is locked or protected. Preview bytes are unavailable.",
            entry.path
        );
    }
    format!("Unable to open {}", entry.path)
}

fn describe_live_entry_read_error(entry: &SourceEntry, error: &anyhow::Error) -> String {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("access is denied")
        || message.contains("access denied")
        || message.contains("sharing violation")
    {
        return describe_live_entry_open_failure(entry);
    }
    if is_virtual_memory_backed_system_file(entry) {
        return format!(
            "Protected virtual-memory file {} skips byte preview to keep the UI responsive.",
            entry.path
        );
    }
    if entry
        .extension
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("sys"))
        || entry.system
    {
        return format!(
            "Live system file {} could not be read safely. Showing metadata only.",
            entry.path
        );
    }
    format!("Preview bytes are unavailable for {}.", entry.path)
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::{
        ArtifactClass, Confidence, ContentSourceKind, FileSystemKind, NameSourceKind, OriginType,
        PathConfidence, PlacementKind, Recoverability, RecoveryPlan, ScanSource, SourceAccessState,
        SourceEntry, SourceEntryClass, SourceKind,
    };

    fn test_source() -> ScanSource {
        ScanSource {
            id: "vol-c".to_string(),
            kind: SourceKind::LogicalVolume,
            device_path: "\\\\.\\C:".to_string(),
            mount_point: Some("C:\\".to_string()),
            display_name: "C:".to_string(),
            volume_label: Some("System".to_string()),
            filesystem: FileSystemKind::Ntfs,
            volume_serial: Some(0x1234),
            total_bytes: 1,
            free_bytes: 1,
            cluster_size: Some(4096),
            is_system: true,
            requires_elevation: true,
        }
    }

    fn test_entry(path: &str) -> SourceEntry {
        SourceEntry {
            name: path.rsplit('\\').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            parent_path: "C:\\".to_string(),
            mft_reference: Some(42),
            parent_reference: Some(5),
            extension: Some("zip".to_string()),
            is_directory: false,
            has_children: Some(false),
            is_metafile: false,
            entry_class: SourceEntryClass::File,
            size: 512,
            created_at: None,
            modified_at: None,
            accessed_at: None,
            hidden: false,
            system: false,
            read_only: false,
            attr_bits: Some(0x20),
            attributes: vec!["archive".to_string()],
            deleted_hits: 0,
            access_state: SourceAccessState::Readable,
        }
    }

    fn denied_sys_entry(path: &str) -> SourceEntry {
        let mut entry = test_entry(path);
        entry.extension = Some("sys".to_string());
        entry.system = true;
        entry.attributes = vec!["system".to_string(), "access_denied".to_string()];
        entry.access_state = SourceAccessState::Denied;
        entry.mft_reference = None;
        entry
    }

    fn resident_artifact(name: &str, bytes: &[u8]) -> ArtifactRecord {
        let mut artifact = ArtifactRecord::new("scan-1", "vol-c", name);
        artifact.kind = ArtifactKind::Zip;
        artifact.family = ArtifactKind::Zip.family();
        artifact.origin_type = OriginType::FilesystemDeletedEntry;
        artifact.confidence = Confidence::High;
        artifact.recoverability = Recoverability::Good;
        artifact.deleted_entry = true;
        artifact.size = bytes.len() as u64;
        artifact.preview_ready = true;
        artifact.placement_kind = PlacementKind::OriginalPath;
        artifact.path_confidence = PathConfidence::Exact;
        artifact.name_source = NameSourceKind::LongName;
        artifact.content_source = ContentSourceKind::ResidentData;
        artifact.artifact_class = ArtifactClass::ValidatedHit;
        artifact.original_path = Some(format!("C:\\{name}"));
        artifact.recovery_plan = RecoveryPlan::ResidentBase64 {
            base64: BASE64.encode(bytes),
            logical_size: bytes.len() as u64,
        };
        artifact
    }

    #[test]
    fn preview_session_uses_entry_hint_without_forcing_entry_lookup() {
        let request = PreviewSessionOpenRequest {
            target: ContentTarget::Entry {
                source_id: "vol-c".to_string(),
                path: "C:\\Users\\jumarf\\broken.zip".to_string(),
            },
            entry_hint: Some(test_entry("C:\\Users\\jumarf\\broken.zip")),
            mode: ArtifactPreviewMode::Hex,
        };
        let (prepared, target) = open_preview_session_for_target(
            |_| Ok(test_source()),
            |_, _| Err(anyhow!("entry lookup should not run")),
            |_, _| Err(anyhow!("artifact lookup should not run")),
            &request,
        )
        .expect("preview session");

        assert_eq!(prepared.resolved_mode, ArtifactPreviewMode::Hex);
        match target {
            PreviewSessionTarget::Entry { entry, .. } => {
                assert_eq!(entry.path, "C:\\Users\\jumarf\\broken.zip");
            }
            PreviewSessionTarget::Artifact(_) => panic!("expected entry target"),
        }
    }

    #[test]
    fn corrupted_archive_preview_falls_back_to_hex_session() {
        let artifact = resident_artifact("broken.zip", b"PK\x03\x04not-a-real-zip");
        let prepared = prepare_artifact_preview_session(&artifact, ArtifactPreviewMode::Auto)
            .expect("session");
        assert_eq!(prepared.resolved_mode, ArtifactPreviewMode::Hex);
        assert!(
            prepared
                .warnings
                .iter()
                .any(|warning| warning.contains("chunked hex view"))
        );
    }

    #[test]
    fn tar_archive_preview_lists_entries() {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let payload = b"hello from tar";
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "docs/readme.txt", &payload[..])
                .expect("append tar entry");
            builder.finish().expect("finish tar archive");
        }

        let mut artifact = resident_artifact("archive.tar", &bytes);
        artifact.kind = ArtifactKind::Tar;
        artifact.family = ArtifactKind::Tar.family();
        let prepared = prepare_artifact_preview_session(&artifact, ArtifactPreviewMode::Auto)
            .expect("session");

        assert_eq!(prepared.resolved_mode, ArtifactPreviewMode::Archive);
        let listing = prepared.archive_listing.expect("tar listing");
        assert_eq!(listing.total_entries, Some(1));
        assert_eq!(listing.entries[0].path, "docs/readme.txt");
    }

    #[test]
    fn gzip_archive_preview_uses_summary_session() {
        let mut artifact = resident_artifact("payload.gz", b"\x1F\x8B\x08placeholder");
        artifact.kind = ArtifactKind::Gzip;
        artifact.family = ArtifactKind::Gzip.family();
        let prepared = prepare_artifact_preview_session(&artifact, ArtifactPreviewMode::Auto)
            .expect("session");

        assert_eq!(prepared.resolved_mode, ArtifactPreviewMode::Archive);
        let listing = prepared.archive_listing.expect("summary listing");
        assert_eq!(listing.total_entries, Some(1));
        assert_eq!(
            listing.entries[0].status,
            ArchivePreviewEntryStatus::Unsupported
        );
    }

    #[test]
    fn denied_sys_preview_session_opens_without_reading_bytes() {
        let entry = denied_sys_entry("C:\\Windows\\System32\\drivers\\blocked.sys");
        let prepared =
            prepare_entry_preview_session(&test_source(), &entry, ArtifactPreviewMode::Auto)
                .expect("session should open");
        assert_eq!(prepared.resolved_mode, ArtifactPreviewMode::Hex);
        assert!(!prepared.warnings.is_empty());
    }

    #[test]
    fn denied_sys_preview_chunk_returns_warning_instead_of_error() {
        let entry = denied_sys_entry("C:\\Windows\\System32\\drivers\\blocked.sys");
        let prepared = PreparedPreviewSession {
            target_key: format!("entry:{}:{}", test_source().id, entry.path),
            requested_mode: ArtifactPreviewMode::Hex,
            resolved_mode: ArtifactPreviewMode::Hex,
            total_size: entry.size,
            summary: source_entry_summary(&entry),
            warnings: Vec::new(),
            archive_listing: None,
        };
        let chunk =
            read_entry_preview_chunk("session-1", &test_source(), &entry, &prepared, 0, 4096)
                .expect("chunk should succeed");
        assert_eq!(chunk.length, 0);
        assert!(chunk.hex_rows.is_empty());
        assert!(
            chunk
                .warnings
                .iter()
                .any(|warning| warning.contains("Preview bytes are unavailable"))
        );
    }

    #[test]
    fn protected_swapfile_uses_hex_without_eager_probe() {
        let mut entry = denied_sys_entry("C:\\swapfile.sys");
        entry.name = "swapfile.sys".to_string();
        entry.path = "C:\\swapfile.sys".to_string();
        entry.access_state = SourceAccessState::Readable;
        entry.attributes = vec!["hidden".to_string(), "system".to_string()];

        let prepared =
            prepare_entry_preview_session(&test_source(), &entry, ArtifactPreviewMode::Auto)
                .expect("session should open");
        assert_eq!(prepared.resolved_mode, ArtifactPreviewMode::Hex);
        assert!(
            prepared
                .warnings
                .iter()
                .any(|warning| warning.contains("chunked hex preview"))
        );
    }

    #[test]
    fn protected_swapfile_signature_is_skipped() {
        let mut entry = denied_sys_entry("C:\\swapfile.sys");
        entry.name = "swapfile.sys".to_string();
        entry.path = "C:\\swapfile.sys".to_string();
        entry.access_state = SourceAccessState::Readable;

        let result = inspect_entry_signature(&test_source(), &entry).expect("signature summary");
        assert_eq!(result.status, ArtifactSignatureStatus::Indeterminate);
        assert_eq!(result.verification_source, "policy:live-system-file");
    }
}

fn source_entry_summary(entry: &SourceEntry) -> Vec<PreviewFact> {
    let mut summary = vec![
        PreviewFact {
            label: "Path".to_string(),
            value: entry.path.clone(),
        },
        PreviewFact {
            label: "Type".to_string(),
            value: if entry.is_directory {
                "directory".to_string()
            } else {
                entry
                    .extension
                    .clone()
                    .unwrap_or_else(|| "file".to_string())
            },
        },
        PreviewFact {
            label: "Size".to_string(),
            value: entry.size.to_string(),
        },
    ];
    if let Some(attr_bits) = entry.attr_bits {
        summary.push(PreviewFact {
            label: "ATTR".to_string(),
            value: format!("0x{attr_bits:04x}"),
        });
    }
    summary
}

fn sanitize_temp_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

trait ArtifactKindExt {
    fn kind_name(&self) -> String;
}

impl ArtifactKindExt for ArtifactKind {
    fn kind_name(&self) -> String {
        format!("{self:?}").to_ascii_lowercase()
    }
}
