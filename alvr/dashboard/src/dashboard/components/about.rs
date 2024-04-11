// use alvr_common::ALVR_VERSION;
use eframe::egui::{RichText, Ui};

pub fn about_tab_ui(ui: &mut Ui) {
    ui.label(RichText::new(format!("MIX streamer v{}", alvr_common::MIX_VERSION)).size(30.0)); //mix version
    ui.label(
r#"Stream VR games from your PC to your headset via Wi-Fi.
Uses technologies like Asynchronous TimeWarp (ATW) and Fixed Foveated Rendering (FFR) for a smoother experience.
"#
    );
    ui.add_space(10.0);
    // ui.hyperlink_to("Visit us on GitHub", "https://github.com/alvr-org/ALVR");
    // ui.hyperlink_to("Join us on Discord", "https://discord.gg/ALVR");
    // ui.hyperlink_to(
    //     "Latest release",
    //     "https://github.com/alvr-org/ALVR/releases/latest",
    // );
}
