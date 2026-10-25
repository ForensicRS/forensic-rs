#![allow(unreachable_code)]
// `Secret` deliberately has no `Serialize` impl -- there must be no path
// from key material into a JSON `Finding`, `ForensicData`, or audit event.
fn main() {
    let secret: forensic_rs::secrets::Secret = unimplemented!();
    let _ = serde_json::to_string(&secret).unwrap();
}
