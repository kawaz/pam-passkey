fn main() {
    // Design rationale: `_probe-dialog` must show exactly the dialog the PAM module shows, so it
    // links the module's own LocalAuthentication shim instead of a copy.
    const TOUCH_ID_SHIM: &str = "../pam_passkey/src/touch_id.m";
    for source in [
        "src/keychain_acl.c",
        "src/browser.c",
        TOUCH_ID_SHIM,
        "build.rs",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }
    cc::Build::new()
        .file("src/keychain_acl.c")
        .warnings(false) // The legacy Keychain ACL APIs are deprecated but required for kSecAttrAccess.
        .compile("keychain_acl");
    cc::Build::new().file("src/browser.c").compile("browser");
    cc::Build::new()
        .file(TOUCH_ID_SHIM)
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .compile("touch_id");
    for framework in [
        "Security",
        "CoreFoundation",
        "CoreServices",
        "LocalAuthentication",
        "Foundation",
    ] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
