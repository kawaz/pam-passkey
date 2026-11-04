fn main() {
    println!("cargo:rerun-if-changed=src/keychain_acl.c");
    cc::Build::new()
        .file("src/keychain_acl.c")
        .warnings(false) // The legacy Keychain ACL APIs are deprecated but required for kSecAttrAccess.
        .compile("keychain_acl");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}
