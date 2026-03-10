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

fn main() -> eframe::Result {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("SysTrace")
            .with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };

    eframe::run_native(
        "SysTrace",
        native_options,
        Box::new(move |cc| {
            let mut app = app::SysTraceApp::new(cc);
            if let Some(path) = args.file.clone() {
                // Delay open until after creation — schedule via a channel trick
                // For simplicity we open directly (the UI loop hasn't started yet,
                // so the first frame will start the background load).
                app.open_file_on_start(path);
            }
            Ok(Box::new(app))
        }),
    )
}
