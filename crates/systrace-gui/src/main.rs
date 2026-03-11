mod app;
mod panels;
mod state;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "systrace-gui", about = "SysTrace — Sysmon forensic analysis tool")]
struct Args {
    /// Path to an EVTXECmd NDJSON export to open on startup.
    file: Option<std::path::PathBuf>,
}

/// Load the bundled application icon from `icon.png` at the project root.
fn load_icon() -> Option<eframe::egui::viewport::IconData> {
    let bytes = include_bytes!("../../../icon.png");
    let img = image::load_from_memory(bytes).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    Some(eframe::egui::viewport::IconData {
        rgba: img.into_raw(),
        width,
        height,
    })
}

fn main() -> eframe::Result {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("SysTrace")
        .with_inner_size([1280.0, 800.0]);
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "SysTrace",
        native_options,
        Box::new(move |cc| {
            let mut app = app::SysTraceApp::new(cc);
            if let Some(path) = args.file.clone() {
                app.open_file_on_start(path);
            }
            Ok(Box::new(app))
        }),
    )
}
