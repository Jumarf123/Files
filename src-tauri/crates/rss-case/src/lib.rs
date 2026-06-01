use anyhow::{Context, Result};
use directories::ProjectDirs;
use rss_core::ScanSnapshot;
use std::{fs, path::PathBuf};

#[derive(Debug, Clone)]
pub struct CaseStore {
    root: PathBuf,
}

impl CaseStore {
    pub fn new() -> Result<Self> {
        let dirs = ProjectDirs::from("dev", "Jumarf", "Files")
            .context("Unable to resolve app-data directory")?;
        let root = dirs.data_local_dir().join("cases");
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn save_snapshot(&self, snapshot: &ScanSnapshot) -> Result<PathBuf> {
        let path = self.root.join(format!("{}.json", snapshot.summary.scan_id));
        fs::write(&path, serde_json::to_vec_pretty(snapshot)?)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        Ok(path)
    }

    pub fn list_snapshots(&self) -> Result<Vec<ScanSnapshot>> {
        let mut snapshots = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            if let Ok(snapshot) = serde_json::from_slice::<ScanSnapshot>(&bytes) {
                snapshots.push(snapshot);
            }
        }
        snapshots.sort_by(|left, right| right.summary.started_at.cmp(&left.summary.started_at));
        Ok(snapshots)
    }
}
