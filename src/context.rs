use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::artifact::Artifact;
use crate::field::Text;

thread_local! {
    pub(crate) static FORENSIC_CONTEXT : RefCell<ForensicContext> = RefCell::new(ForensicContext::default());
}

#[derive(Default, Debug, Clone)]
pub struct ForensicContext {
    pub host: String,
    pub artifact: Artifact,
    pub tenant: String,
    /// Extensible key-value metadata for custom analysis context.
    pub metadata: BTreeMap<Text, Text>,
}

/// Simplifys the creation of new events with the context of the analysis: artifact being processed, name of the machine where the artifacts came from and the name of the client/tenant.
pub fn initialize_context(context: ForensicContext) {
    let _ = FORENSIC_CONTEXT.with(|v| {
        let mut brw = v.borrow_mut();
        *brw = context;
        Ok::<(), ()>(())
    });
    // Wait for local_key_cell_methods
    //COMPONENT_LOGGER.replace(msngr);
}

/// Gets the context of the analysis
pub fn context() -> ForensicContext {
    FORENSIC_CONTEXT.with(|context| context.borrow().clone())
}

/// Changes the type of artifact being processed by the current thread
pub fn set_artifact<A: Into<Artifact>>(artifact: A) {
    let artifact = artifact.into();
    FORENSIC_CONTEXT.with(|context| {
        let mut borrowed = context.borrow_mut();
        borrowed.artifact = artifact;
    })
}

/// Change the tenant ID for which artifacts are being processed by the current thread
pub fn set_tenant(tenant: String) {
    FORENSIC_CONTEXT.with(|context| {
        let mut borrowed = context.borrow_mut();
        borrowed.tenant = tenant;
    })
}
/// Change the name of the computer for which artifacts are being processed by the current thread
pub fn set_host(host: String) {
    FORENSIC_CONTEXT.with(|context| {
        let mut borrowed = context.borrow_mut();
        borrowed.host = host;
    })
}

#[test]
fn should_initialize_and_read_back_context() {
    // `ForensicData` no longer has a zero-argument `Default`/context-pulling
    // constructor — every `ForensicData` requires a real `ProvenanceId`
    // (see `src/data.rs`), which the thread-local `ForensicContext` has no
    // way to supply. This test now only covers the thread-local context
    // mechanism itself, not `ForensicData`.
    use crate::artifact::Artifact;
    use crate::artifact::RegistryArtifacts;
    let context = ForensicContext {
        artifact: RegistryArtifacts::AutoRuns.into(),
        host: "Agent007".into(),
        tenant: "MI6".into(),
        metadata: BTreeMap::new(),
    };
    initialize_context(context);
    let restored = crate::context::context();
    assert_eq!("Agent007", restored.host);
    assert_eq!("MI6", restored.tenant);
    assert_eq!(
        Into::<Artifact>::into(RegistryArtifacts::AutoRuns),
        restored.artifact
    );
}
