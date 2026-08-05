#![allow(unreachable_code)]
// `Tracked<T>` deliberately has no `Deref`/`DerefMut` impl. If `*tracked`
// compiled, `let t = *entry.modified;` would silently discard provenance
// with no diagnostic — the escape hatch must be the explicitly-named
// `into_untracked()` instead.
fn main() {
    let tracked: forensic_rs::provenance::Tracked<u32> = unimplemented!();
    let _value: u32 = *tracked;
}
