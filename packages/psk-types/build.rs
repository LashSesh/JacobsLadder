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
    let error_catalog = psk_codegen::load_error_catalog(&root);
    let sort_registry = psk_codegen::load_sort_registry(&root);
    let object_schemas = psk_codegen::load_object_schemas(&root);

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(
        out_dir.join("module_id.rs"),
        psk_codegen::generate_module_id_enum(&module_map),
    )
    .unwrap();
    fs::write(
        out_dir.join("port_id.rs"),
        psk_codegen::generate_port_id_enum(&port_registry),
    )
    .unwrap();
    fs::write(
        out_dir.join("error.rs"),
        psk_codegen::generate_error_enum(&error_catalog),
    )
    .unwrap();
    fs::write(
        out_dir.join("payloads.rs"),
        psk_codegen::generate_payload_markers(&port_registry),
    )
    .unwrap();
    fs::write(
        out_dir.join("sort_id.rs"),
        psk_codegen::generate_sort_id_enum(&sort_registry),
    )
    .unwrap();
    fs::write(
        out_dir.join("object_structs.rs"),
        psk_codegen::generate_object_structs(&object_schemas),
    )
    .unwrap();
}
