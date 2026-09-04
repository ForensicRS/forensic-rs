//! Public, always-compiled test-double implementations of this crate's core
//! traits, for downstream crates writing tests against `forensic-rs` without
//! hitting real backends (disk, a live registry, a live event log, a real
//! database).
//!
//! Reachable at `forensic_rs::utils::testing::*` or, more discoverably, via
//! `forensic_rs::prelude::testing::*`.

mod db;
mod events;
mod factories;
mod hooks;
mod parser;
mod registry;
mod vfs;

pub use db::{InMemoryForensicDb, InMemoryTable};
pub use events::{basic_event_log, TestingEventLogReader};
pub use factories::TestingFormatFactory;
pub use hooks::TestingProviderHook;
pub use parser::{TestParserFactory, TestParserFactoryBuilder};
pub use registry::{MountedCell, TestingRegistry};
pub use vfs::{InMemoryVirtualFile, InMemoryVirtualFileSystem};

use crate::provenance::{Acquisition, ProvenanceId, Recovery, SourceKey};

/// A real, legitimately-minted [`ProvenanceId`] from a throwaway store, for
/// tests that need one but aren't testing provenance itself.
///
/// This is not a forgery bypass: it calls the same public
/// `register_source`/`mint` API any real caller would use, on a fresh
/// throwaway store — it isn't re-exported into the prelude and adds no new
/// path to the mint API surface.
pub fn test_provenance_id() -> ProvenanceId {
    crate::provenance::ProvenanceStore::new()
        .register_source(SourceKey::Synthetic("test".to_string()))
        .mint(Acquisition::LiveApi, Recovery::Allocated)
}

pub fn init_testing_logger() {
    let rcv = crate::logging::testing_logger_dummy();
    std::thread::spawn(move || loop {
        let msg = match rcv.recv() {
            Ok(v) => v,
            Err(_) => return,
        };
        println!(
            "{:?} - {} - {}:{} - {}",
            msg.level, msg.module, msg.file, msg.line, msg.data
        );
    });
}
