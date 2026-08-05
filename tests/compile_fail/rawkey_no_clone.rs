// `RawKey` is deliberately not `Copy`/`Clone`: duplicating one would let a
// caller hold two "owning" references to the same backend resource,
// defeating `RegKey`'s close-on-drop guarantee (which assumes it holds the
// unique `RawKey` for its resource). Using it after a move must not compile.
use forensic_rs::traits::registry::RawKey;

fn main() {
    let key = RawKey::from_raw(0);
    let _moved = key;
    let _ = key.raw();
}
