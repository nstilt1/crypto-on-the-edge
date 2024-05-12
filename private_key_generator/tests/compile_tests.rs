use trybuild::TestCases;

#[test]
fn test_compile_errors() {
    let t = trybuild::TestCases::new();
    // for some reason, it is required to pass a test case before it can fail
    // tests successfully
    t.pass("tests/empty.rs");
    t.compile_fail("tests/compile_fails/*.rs");
}

#[test]
fn compiler_error_dbg() {
    let t = TestCases::new();
    t.pass("tests/empty.rs");
    t.compile_fail("tests/compile_fails/version_lifetime_too_short.rs")
}

#[test]
fn test_compilation() {
    let t = TestCases::new();

    t.pass("tests/compile_passes/*.rs");
}
