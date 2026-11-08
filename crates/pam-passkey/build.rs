fn main() {
    println!("cargo:rerun-if-changed=src/keychain_acl.c");
    println!("cargo:rerun-if-changed=src/browser.c");
    println!("cargo:rerun-if-changed=build.rs");
    cc::Build::new()
        .file("src/keychain_acl.c")
        .warnings(false) // The legacy Keychain ACL APIs are deprecated but required for kSecAttrAccess.
        .compile("keychain_acl");
    cc::Build::new().file("src/browser.c").compile("browser");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib=framework=CoreServices");
}
