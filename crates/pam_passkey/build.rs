fn main() {
    cc::Build::new()
        .file("src/signature.c")
        .compile("pam_signature");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}
