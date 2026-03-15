fn main() {
    // Only needed when compiling for Windows.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let ico_path = std::path::Path::new(&out_dir).join("icon.ico");

    // Convert icon.png → multi-size icon.ico
    let src = image::open("../../icon.png").expect("failed to open icon.png");
    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [16u32, 32, 48, 256] {
        let rgba = src
            .resize_exact(size, size, image::imageops::FilterType::Lanczos3)
            .into_rgba8();
        let icon_img = ico::IconImage::from_rgba_data(size, size, rgba.into_raw());
        icon_dir.add_entry(
            ico::IconDirEntry::encode(&icon_img).expect("failed to encode ico entry"),
        );
    }
    let f = std::fs::File::create(&ico_path).expect("failed to create icon.ico");
    icon_dir.write(f).expect("failed to write icon.ico");

    // Embed into the Windows PE binary.
    let mut res = winresource::WindowsResource::new();
    res.set_icon(ico_path.to_str().unwrap());
    res.compile().expect("failed to compile Windows resources");

    println!("cargo:rerun-if-changed=../../icon.png");
}
