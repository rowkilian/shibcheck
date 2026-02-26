use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use notify_debouncer_mini::{new_debouncer, DebouncedEventKind};

/// Watch a directory for changes and run the callback on each change.
/// The callback is also invoked once immediately on startup.
pub fn watch_and_run<F>(dir: &Path, mut callback: F) -> anyhow::Result<()>
where
    F: FnMut(),
{
    // Run once immediately
    callback();

    let (tx, rx) = mpsc::channel();

    let mut debouncer = new_debouncer(Duration::from_millis(500), tx)?;
    debouncer
        .watcher()
        .watch(dir, notify::RecursiveMode::NonRecursive)?;

    eprintln!("\nWatching {} for changes (Ctrl-C to stop)…", dir.display());

    loop {
        match rx.recv() {
            Ok(Ok(events)) => {
                let has_xml = events.iter().any(|e| {
                    e.kind == DebouncedEventKind::Any
                        && e.path.extension().is_some_and(|ext| ext == "xml")
                });
                if has_xml {
                    eprintln!("\n--- File change detected, re-running checks ---\n");
                    callback();
                }
            }
            Ok(Err(e)) => {
                eprintln!("Watch error: {}", e);
            }
            Err(e) => {
                eprintln!("Channel error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
