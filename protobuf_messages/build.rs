fn main() {
    prost_build::Config::new()
        .out_dir("src/generated")
        .compile_protos(
            &[
                "src/protos/response.proto",
                "src/protos/request.proto"
            ], 
            &["src/"])
        .unwrap();
}
