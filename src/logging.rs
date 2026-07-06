use crate::config::LoggingConfig;
use anyhow::Context;
use std::{
    cmp::Reverse,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub struct LoggingGuard {
    _guard: WorkerGuard,
}

pub fn init_logging(config: &LoggingConfig) -> anyhow::Result<LoggingGuard> {
    let directory = Path::new(&config.directory);
    fs::create_dir_all(directory)
        .with_context(|| format!("failed to create log directory {}", directory.display()))?;
    cleanup_logs(config)?;

    let file_name = format!("{}.log", config.file_prefix);
    let file_appender = tracing_appender::rolling::daily(directory, file_name);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let filter = EnvFilter::try_new(&config.level).unwrap_or_else(|_| EnvFilter::new("info"));
    let file_layer = fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .with_target(true);
    let stdout_layer = config
        .stdout
        .then(|| fmt::layer().with_writer(std::io::stdout).with_target(true));

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stdout_layer)
        .init();

    Ok(LoggingGuard { _guard: guard })
}

pub fn cleanup_logs(config: &LoggingConfig) -> anyhow::Result<()> {
    let directory = Path::new(&config.directory);
    if !directory.exists() {
        return Ok(());
    }

    let prefix = format!("{}.log", config.file_prefix);
    let mut files = log_files(directory, &prefix)?;
    let now = SystemTime::now();

    if config.retention_days > 0 {
        let max_age = Duration::from_secs(config.retention_days * 24 * 60 * 60);
        for file in &files {
            if let Ok(age) = now.duration_since(file.modified_at)
                && age > max_age
            {
                let _ = fs::remove_file(&file.path);
            }
        }
    }

    files = log_files(directory, &prefix)?;
    files.sort_by_key(|file| Reverse(file.modified_at));
    for file in files.into_iter().skip(config.retention_files) {
        let _ = fs::remove_file(file.path);
    }

    Ok(())
}

#[derive(Debug)]
struct LogFile {
    path: PathBuf,
    modified_at: SystemTime,
}

fn log_files(directory: &Path, prefix: &str) -> anyhow::Result<Vec<LogFile>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read log directory {}", directory.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(prefix) {
            continue;
        }

        let metadata = entry.metadata()?;
        files.push(LogFile {
            path: entry.path(),
            modified_at: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        });
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, thread};

    #[test]
    fn cleanup_keeps_newest_configured_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = LoggingConfig {
            directory: dir.path().to_string_lossy().to_string(),
            file_prefix: "honeypot".to_string(),
            retention_files: 2,
            retention_days: 0,
            ..LoggingConfig::default()
        };

        for day in 1..=3 {
            fs::write(dir.path().join(format!("honeypot.log.2026-07-0{day}")), "x").unwrap();
            thread::sleep(Duration::from_millis(5));
        }

        cleanup_logs(&config).unwrap();

        let remaining = log_files(dir.path(), "honeypot.log").unwrap();
        assert_eq!(remaining.len(), 2);
    }
}
