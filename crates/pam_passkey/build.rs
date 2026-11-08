fn main() {
    for source in [
        "src/signature.c",
        "src/process.c",
        "src/touch_id.m",
        "build.rs",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }
    cc::Build::new()
        .file("src/signature.c")
        .file("src/process.c")
        .compile("pam_passkey_c");
    cc::Build::new()
        .file("src/touch_id.m")
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .compile("pam_passkey_objc");
    for framework in [
        "LocalAuthentication",
        "Foundation",
        "Security",
        "CoreFoundation",
    ] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
