// `RegKey<'r>` is tied to the `&'r dyn Registry` it was opened from. It must
// not be possible to return a `RegKey` whose reader has gone out of scope —
// this is the RFC 0001 P2 fix's headline guarantee: a handle-lifetime bug
// that compiled under the old `RegHiveKey`/`Hkey(isize)` design is a
// compile error here instead of a runtime one.
use forensic_rs::traits::registry::{Registry, RegKey, RegistryExt};

fn leak() -> RegKey<'static> {
    let reg = forensic_rs::utils::testing::TestingRegistry::new();
    let reg: &dyn Registry = &reg;
    reg.key("HKLM").unwrap()
}

fn main() {
    let _ = leak();
}
