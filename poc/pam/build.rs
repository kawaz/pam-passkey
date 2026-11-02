fn main() {
    cc::Build::new().file("src/parent_pid.c").compile("pam_poc_parent_pid");
    cc::Build::new()
        .file("src/touch_id.m")
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .compile("pam_poc_touch_id");
    println!("cargo:rustc-link-lib=pam");
    for framework in ["LocalAuthentication", "Foundation"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
