#![allow(unreachable_code)]
// `Secret` deliberately has no `Debug` impl -- there must be no path from a
// `{:?}` in a log line to key material reaching stderr/a log file.
fn main() {
    let secret: forensic_rs::secrets::Secret = unimplemented!();
    println!("{:?}", secret);
}
