#![allow(unreachable_code)]
// `Secret` deliberately has no `Clone` impl -- key material must have one
// owner with one `Drop`-triggered zeroization, never an uncontrolled number
// of copies each needing their own zeroization.
fn main() {
    let secret: forensic_rs::secrets::Secret = unimplemented!();
    let _second = secret.clone();
}
