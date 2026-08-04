use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = psk_codegen::workspace_root(&manifest_dir);
    for f in psk_codegen::tracked_register_files(&root) {
        println!("cargo:rerun-if-changed={}", f.display());
    }
    let module_map = psk_codegen::load_module_map(&root);
    let port_registry = psk_codegen::load_port_registry(&root);
    let object_schemas = psk_codegen::load_object_schemas(&root);
    let known_objects = psk_codegen::known_object_names(&object_schemas);
    let stubs = psk_codegen::generate_port_stubs_for_package(
        &module_map,
        &port_registry,
        "psk-dependency",
        &known_objects,
    );
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("port_stubs.rs"), stubs).unwrap();
}
