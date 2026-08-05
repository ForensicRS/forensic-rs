// `RegKey`'s fields are private, so there is no way for external code to
// extract a `RawKey` from a `RegKey` and hand it to a *different* reader's
// methods — the only entry points are `RegKey`'s own inherent methods,
// which always call back into the reader that minted the key. This fixture
// proves the actual enforcement mechanism: direct field access is rejected.
use forensic_rs::traits::registry::RegistryExt;
use forensic_rs::utils::testing::TestingRegistry;

fn main() {
    let reader_a = TestingRegistry::new();
    let key = reader_a.key("HKLM").unwrap();
    let _raw = key.raw;
}
