//! Compile-fail proof that the provenance model's forgery guarantees are
//! enforced by the type system, not just documented convention. Each fixture
//! under `tests/compile_fail/` must fail to compile; see `provenance` module
//! docs for the guarantee each one exercises.

#[test]
fn compile_fail_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
    // These prove a type has no `Serialize` impl, which only means something
    // when the `serde` feature puts `Serialize` in scope at all.
    #[cfg(feature = "serde")]
    t.compile_fail("tests/compile_fail/serde/*.rs");
}
