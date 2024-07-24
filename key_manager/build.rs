#[cfg(feature = "prost-build")]
fn main() {
    prost_build::Config::new()
        .out_dir("src/generated")
        .compile_protos(
            &["protos/server_client_ecdh_ecdsa_mode.proto"],
            &["protos/"],
        )
        .unwrap()
}
#[cfg(not(feature = "prost-build"))]
fn main() {}
