use std::cell::RefCell;

use crate::artifact::Artifact;

thread_local! {
    pub(crate) static FORENSIC_CONTEXT : RefCell<ForensicContext> = RefCell::new(ForensicContext::default());
}


#[derive(Default, Debug, Clone)]
pub struct ForensicContext {
    pub host : String,
    pub artifact : Artifact,
    pub tenant : String
}

pub fn initialize_context(context: ForensicContext) {
    let _ = FORENSIC_CONTEXT.with(|v| {
        let mut brw = v.borrow_mut();
        *brw = context;
        Ok::<(), ()>(())
    });
    // Wait for local_key_cell_methods
    //COMPONENT_LOGGER.replace(msngr);
}

pub fn context() -> ForensicContext {
    FORENSIC_CONTEXT.with(|context| context.borrow().clone())
}

#[test]
fn should_initialize_log_with_context() {
    use crate::artifact::Artifact;
    use crate::artifact::RegistryArtifacts;
    let context = ForensicContext {
        artifact : RegistryArtifacts::AutoRuns.into(),
        host : "Agent007".into(),
        tenant : "MI6".into()
    };
    initialize_context(context);
    let log = crate::data::ForensicData::default();
    assert_eq!("Agent007", log.host());
    assert_eq!("MI6", TryInto::<&str>::try_into(log.field(crate::dictionary::ARTIFACT_TENANT).unwrap()).unwrap());
    assert_eq!(Into::<Artifact>::into(RegistryArtifacts::AutoRuns), *log.artifact());
}