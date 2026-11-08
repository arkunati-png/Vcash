// Release builds are a GUI program: no console window.
#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

use voltcash_core::app;

const LOGO_PNG: &[u8] = include_bytes!("../assets/logo-256.png");

fn main() -> eframe::Result<()> {
    let logo = image::load_from_memory(LOGO_PNG)
        .expect("the embedded logo is a valid PNG")
        .into_rgba8();
    let (width, height) = logo.dimensions();
    let icon = eframe::egui::IconData {
        rgba: logo.clone().into_raw(),
        width,
        height,
    };

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Voltcash Core")
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([820.0, 580.0])
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "Voltcash Core",
        options,
        Box::new(move |cc| Ok(Box::new(app::VoltCore::new(cc, logo)))),
    )
}
