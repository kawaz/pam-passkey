fn main() {
    cc::Build::new()
        .file("src/keychain_acl.c")
        .compile("kcpoc_keychain_acl");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}
