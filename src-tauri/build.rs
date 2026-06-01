fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=../resources/installer/files.manifest");
        println!("cargo:rerun-if-changed=icons/icon.ico");

        let windows = tauri_build::WindowsAttributes::new()
            .window_icon_path("icons/icon.ico")
            .app_manifest(include_str!("../resources/installer/files.manifest"));
        let attributes = tauri_build::Attributes::new().windows_attributes(windows);
        tauri_build::try_build(attributes).expect("failed to run tauri build script");
    }

    #[cfg(not(target_os = "windows"))]
    tauri_build::build()
}
