//! The wallet UI.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Color32, ColorImage, Context, CornerRadius, Frame, Layout, Margin, RichText,
    Sense, Stroke, TextureHandle, TextureOptions, Ui, Vec2,
};
use rand::seq::SliceRandom;
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{self, Addresses, RecipientKind};
use crate::network::{format_volt, parse_volt};
use crate::node::{NodeMonitor, NodeStatus};
use crate::settings::{self, Settings};
use crate::vault;

// Palette, taken from the Voltcash logo.
const ACCENT: Color32 = Color32::from_rgb(184, 82, 84);
const ACCENT_HOVER: Color32 = Color32::from_rgb(204, 100, 102);
const BG: Color32 = Color32::from_rgb(18, 14, 15);
const PANEL: Color32 = Color32::from_rgb(27, 21, 23);
const CARD: Color32 = Color32::from_rgb(36, 28, 30);
const LINE: Color32 = Color32::from_rgb(58, 46, 48);
const TEXT: Color32 = Color32::from_rgb(243, 236, 236);
const MUTED: Color32 = Color32::from_rgb(163, 154, 155);
const OK: Color32 = Color32::from_rgb(95, 179, 124);
const WARN: Color32 = Color32::from_rgb(224, 170, 80);
const BAD: Color32 = Color32::from_rgb(226, 98, 98);

/// The smallest fee tier `volt-core` charges, in zats (`fee.rs`: 10_000 / 20_000).
const MIN_FEE_ZATS: u64 = 10_000;

// ---------------------------------------------------------------------------------------------
// Background jobs: Argon2 takes a moment, so it never runs on the UI thread.

struct Job<T>(mpsc::Receiver<T>);

impl<T: Send + 'static> Job<T> {
    fn spawn(ctx: &Context, work: impl FnOnce() -> T + Send + 'static) -> Self {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(work());
            ctx.request_repaint();
        });
        Self(rx)
    }

    fn poll(&self) -> Option<T> {
        self.0.try_recv().ok()
    }
}

// ---------------------------------------------------------------------------------------------
// Screens

enum Screen {
    Welcome,
    Create(Create),
    Restore(Restore),
    Unlock(Unlock),
    Home(Box<Home>),
}

struct Create {
    phrase: Zeroizing<String>,
    /// Zero-based indexes of the words the user must re-enter to prove they wrote it down.
    check: [usize; 3],
    answers: [String; 3],
    password: String,
    confirm: String,
    saved: bool,
    step: u8,
    job: Option<Job<Result<Addresses, String>>>,
    error: Option<String>,
}

impl Create {
    fn new() -> Self {
        let phrase = keys::generate_phrase();
        let mut indexes: Vec<usize> = (0..24).collect();
        indexes.shuffle(&mut rand::thread_rng());
        let mut check = [indexes[0], indexes[1], indexes[2]];
        check.sort_unstable();
        Self {
            phrase,
            check,
            answers: Default::default(),
            password: String::new(),
            confirm: String::new(),
            saved: false,
            step: 0,
            job: None,
            error: None,
        }
    }
}

#[derive(Default)]
struct Restore {
    phrase: String,
    password: String,
    confirm: String,
    job: Option<Job<Result<Addresses, String>>>,
    error: Option<String>,
}

#[derive(Default)]
struct Unlock {
    password: String,
    job: Option<Job<Result<Addresses, String>>>,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Receive,
    Send,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Unified,
    Shielded,
    Sapling,
    Transparent,
}

struct Home {
    addrs: Addresses,
    tab: Tab,
    receive: Kind,
    copied: Option<Instant>,
    send: SendForm,
    node_input: String,
    reveal: Reveal,
    lock: bool,
}

#[derive(Default)]
struct SendForm {
    to: String,
    amount: String,
    memo: String,
}

#[derive(Default)]
struct Reveal {
    password: String,
    job: Option<Job<Result<Zeroizing<String>, String>>>,
    shown: Option<Zeroizing<String>>,
    error: Option<String>,
}

struct Shared {
    logo: TextureHandle,
    settings: Settings,
    monitor: NodeMonitor,
}

pub struct VoltWallet {
    shared: Shared,
    screen: Screen,
}

impl VoltWallet {
    pub fn new(cc: &eframe::CreationContext<'_>, logo: image::RgbaImage) -> Self {
        apply_theme(&cc.egui_ctx);
        let (w, h) = logo.dimensions();
        let image = ColorImage::from_rgba_unmultiplied([w as usize, h as usize], logo.as_raw());
        let texture = cc
            .egui_ctx
            .load_texture("volt-logo", image, TextureOptions::LINEAR);

        let settings = Settings::load();
        let monitor = NodeMonitor::start(settings.node_addr.clone(), cc.egui_ctx.clone());
        let screen = if settings::vault_path().exists() {
            Screen::Unlock(Unlock::default())
        } else {
            Screen::Welcome
        };
        Self {
            shared: Shared {
                logo: texture,
                settings,
                monitor,
            },
            screen,
        }
    }
}

impl eframe::App for VoltWallet {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        let next = match &mut self.screen {
            Screen::Welcome => welcome_ui(ctx, &self.shared),
            Screen::Create(s) => create_ui(ctx, &self.shared, s),
            Screen::Restore(s) => restore_ui(ctx, &self.shared, s),
            Screen::Unlock(s) => unlock_ui(ctx, &self.shared, s),
            Screen::Home(h) => {
                home_ui(ctx, &mut self.shared, h);
                None
            }
        };
        if let Some(next) = next {
            self.screen = next;
        }
        if matches!(&self.screen, Screen::Home(h) if h.lock) {
            self.screen = Screen::Unlock(Unlock::default());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Theme and small widgets

fn apply_theme(ctx: &Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = Color32::from_rgb(14, 11, 12);
    v.faint_bg_color = CARD;
    v.override_text_color = Some(TEXT);
    v.hyperlink_color = ACCENT_HOVER;
    v.selection.bg_fill = ACCENT.linear_multiply(0.55);
    v.selection.stroke = Stroke::new(1.0, TEXT);
    let radius = CornerRadius::same(8);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = radius;
    }
    v.widgets.inactive.bg_fill = CARD;
    v.widgets.inactive.weak_bg_fill = CARD;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(50, 39, 41);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    v.widgets.active.weak_bg_fill = ACCENT;
    ctx.set_visuals(v);

    ctx.style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(10.0, 10.0);
        s.spacing.button_padding = Vec2::new(14.0, 8.0);
        s.spacing.interact_size.y = 32.0;
    });
}

fn card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

fn notice(ui: &mut Ui, color: Color32, text: &str) {
    Frame::new()
        .fill(color.linear_multiply(0.12))
        .stroke(Stroke::new(1.0, color.linear_multiply(0.6)))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(text).color(TEXT));
        });
}

fn primary(ui: &mut Ui, text: &str, enabled: bool) -> bool {
    let button = egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
        .fill(if enabled {
            ACCENT
        } else {
            ACCENT.linear_multiply(0.35)
        })
        .min_size(Vec2::new(140.0, 38.0));
    let response = ui.add_enabled(enabled, button);
    if response.hovered() && enabled {
        ui.painter().rect_filled(
            response.rect,
            CornerRadius::same(8),
            ACCENT_HOVER.linear_multiply(0.35),
        );
    }
    response.clicked()
}

fn secondary(ui: &mut Ui, text: &str) -> bool {
    ui.add(egui::Button::new(text).min_size(Vec2::new(110.0, 34.0)))
        .clicked()
}

fn field_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).color(MUTED).size(13.0));
}

fn password_field(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .hint_text(hint)
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(10, 8)),
    )
}

fn logo_image(shared: &Shared, size: f32) -> egui::Image<'_> {
    egui::Image::new((shared.logo.id(), Vec2::splat(size)))
        .corner_radius(CornerRadius::same((size * 0.2) as u8))
}

/// A centered column on an otherwise empty page.
fn page(ctx: &Context, shared: &Shared, title: &str, subtitle: &str, add: impl FnOnce(&mut Ui)) {
    egui::CentralPanel::default().show(ctx, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            let width = 480.0_f32.min(ui.available_width() - 32.0);
            let pad = ((ui.available_width() - width) / 2.0).max(0.0);
            ui.horizontal_top(|ui| {
                ui.add_space(pad);
                ui.vertical(|ui| {
                    ui.set_width(width);
                    ui.add_space(28.0);
                    ui.add(logo_image(shared, 72.0));
                    ui.add_space(4.0);
                    ui.label(RichText::new(title).size(26.0).strong());
                    ui.label(RichText::new(subtitle).color(MUTED));
                    ui.add_space(10.0);
                    add(ui);
                    ui.add_space(28.0);
                });
            });
        });
    });
}

fn passwords_ok(password: &str, confirm: &str) -> Result<(), &'static str> {
    if password.chars().count() < 8 {
        Err("Use a password of at least 8 characters.")
    } else if password != confirm {
        Err("The two passwords do not match.")
    } else {
        Ok(())
    }
}

fn error_line(ui: &mut Ui, error: &Option<String>) {
    if let Some(error) = error {
        ui.label(RichText::new(error).color(BAD));
    }
}

// ---------------------------------------------------------------------------------------------
// Welcome / create / restore / unlock

fn welcome_ui(ctx: &Context, shared: &Shared) -> Option<Screen> {
    let mut next = None;
    page(
        ctx,
        shared,
        "Voltcash Wallet",
        "Optional privacy, built on librustzcash.",
        |ui| {
            card(ui, |ui| {
                ui.label(RichText::new("Create a new wallet").strong().size(17.0));
                ui.label(
                    RichText::new(
                        "Generates a 24-word recovery phrase. Anyone with the phrase controls your coins, and nobody can recover it for you.",
                    )
                    .color(MUTED),
                );
                if primary(ui, "Create wallet", true) {
                    next = Some(Screen::Create(Create::new()));
                }
            });
            card(ui, |ui| {
                ui.label(
                    RichText::new("Restore from recovery phrase")
                        .strong()
                        .size(17.0),
                );
                ui.label(RichText::new("Bring back a wallet you made before.").color(MUTED));
                if secondary(ui, "Restore wallet") {
                    next = Some(Screen::Restore(Restore::default()));
                }
            });
        },
    );
    next
}

fn create_ui(ctx: &Context, shared: &Shared, s: &mut Create) -> Option<Screen> {
    let mut next = None;

    if let Some(result) = s.job.as_ref().and_then(Job::poll) {
        s.job = None;
        match result {
            Ok(addrs) => return Some(Screen::Home(Box::new(Home::new(addrs, &shared.settings)))),
            Err(e) => s.error = Some(e),
        }
    }

    page(
        ctx,
        shared,
        "Your recovery phrase",
        "Write these 24 words down, in order, on paper.",
        |ui| {
            if s.step == 0 {
                card(ui, |ui| {
                    egui::Grid::new("phrase")
                        .num_columns(4)
                        .spacing([18.0, 8.0])
                        .show(ui, |ui| {
                            for (i, word) in s.phrase.split(' ').enumerate() {
                                ui.label(
                                    RichText::new(format!("{:>2}. {word}", i + 1))
                                        .monospace()
                                        .size(15.0),
                                );
                                if i % 4 == 3 {
                                    ui.end_row();
                                }
                            }
                        });
                });
                notice(
                    ui,
                    WARN,
                    "Never type this phrase into a website or share it. Voltcash staff will never ask for it.",
                );
                ui.checkbox(
                    &mut s.saved,
                    "I have written the phrase down and stored it safely",
                );
                ui.horizontal(|ui| {
                    if secondary(ui, "Back") {
                        next = Some(Screen::Welcome);
                    }
                    if primary(ui, "Continue", s.saved) {
                        s.step = 1;
                    }
                });
            } else {
                card(ui, |ui| {
                    ui.label(RichText::new("Confirm your backup").strong().size(17.0));
                    for (answer, idx) in s.answers.iter_mut().zip(s.check) {
                        field_label(ui, &format!("Word #{}", idx + 1));
                        ui.add(
                            egui::TextEdit::singleline(answer)
                                .desired_width(f32::INFINITY)
                                .margin(Margin::symmetric(10, 8)),
                        );
                    }
                });
                card(ui, |ui| {
                    ui.label(
                        RichText::new("Protect this device's copy")
                            .strong()
                            .size(17.0),
                    );
                    ui.label(
                        RichText::new("The password encrypts the phrase on this computer. It is not a substitute for the phrase.")
                            .color(MUTED),
                    );
                    field_label(ui, "Password");
                    password_field(ui, &mut s.password, "at least 8 characters");
                    field_label(ui, "Repeat password");
                    password_field(ui, &mut s.confirm, "");
                });

                let words: Vec<&str> = s.phrase.split(' ').collect();
                let words_ok = s
                    .check
                    .iter()
                    .zip(&s.answers)
                    .all(|(idx, a)| a.trim().eq_ignore_ascii_case(words[*idx]));
                let pw = passwords_ok(&s.password, &s.confirm);
                if !words_ok && s.answers.iter().any(|a| !a.is_empty()) {
                    ui.label(RichText::new("The words do not match your phrase yet.").color(WARN));
                }
                if let (Err(e), true) = (pw, !s.password.is_empty() && !s.confirm.is_empty()) {
                    ui.label(RichText::new(e).color(WARN));
                }
                error_line(ui, &s.error);

                let busy = s.job.is_some();
                ui.horizontal(|ui| {
                    if secondary(ui, "Back") && !busy {
                        s.step = 0;
                    }
                    let label = if busy { "Creating..." } else { "Create wallet" };
                    if primary(ui, label, words_ok && pw.is_ok() && !busy) {
                        let phrase = s.phrase.clone();
                        let mut password = std::mem::take(&mut s.password);
                        s.confirm.zeroize();
                        s.job = Some(Job::spawn(ctx, move || {
                            let result = finish_create(&phrase, &password);
                            password.zeroize();
                            result
                        }));
                    }
                });
            }
        },
    );
    next
}

fn finish_create(phrase: &str, password: &str) -> Result<Addresses, String> {
    let addrs = keys::addresses(&keys::viewing_key(phrase)?)?;
    vault::create(&settings::vault_path(), phrase, password).map_err(|e| e.to_string())?;
    Ok(addrs)
}

fn restore_ui(ctx: &Context, shared: &Shared, s: &mut Restore) -> Option<Screen> {
    let mut next = None;

    if let Some(result) = s.job.as_ref().and_then(Job::poll) {
        s.job = None;
        match result {
            Ok(addrs) => return Some(Screen::Home(Box::new(Home::new(addrs, &shared.settings)))),
            Err(e) => s.error = Some(e),
        }
    }

    page(
        ctx,
        shared,
        "Restore wallet",
        "Enter your 24-word recovery phrase.",
        |ui| {
            card(ui, |ui| {
                field_label(ui, "Recovery phrase");
                ui.add(
                    egui::TextEdit::multiline(&mut s.phrase)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace)
                        .margin(Margin::symmetric(10, 8)),
                );
                field_label(ui, "New password for this device");
                password_field(ui, &mut s.password, "at least 8 characters");
                field_label(ui, "Repeat password");
                password_field(ui, &mut s.confirm, "");
            });
            let pw = passwords_ok(&s.password, &s.confirm);
            if let (Err(e), true) = (pw, !s.password.is_empty() && !s.confirm.is_empty()) {
                ui.label(RichText::new(e).color(WARN));
            }
            error_line(ui, &s.error);
            let busy = s.job.is_some();
            ui.horizontal(|ui| {
                if secondary(ui, "Back") && !busy {
                    s.phrase.zeroize();
                    next = Some(Screen::Welcome);
                }
                let label = if busy {
                    "Restoring..."
                } else {
                    "Restore wallet"
                };
                if primary(
                    ui,
                    label,
                    pw.is_ok() && !s.phrase.trim().is_empty() && !busy,
                ) {
                    let mut phrase = std::mem::take(&mut s.phrase);
                    let mut password = std::mem::take(&mut s.password);
                    s.confirm.zeroize();
                    s.error = None;
                    s.job = Some(Job::spawn(ctx, move || {
                        let result = keys::normalize_phrase(&phrase)
                            .and_then(|normal| finish_create(&normal, &password));
                        phrase.zeroize();
                        password.zeroize();
                        result
                    }));
                }
            });
        },
    );
    next
}

fn unlock_ui(ctx: &Context, shared: &Shared, s: &mut Unlock) -> Option<Screen> {
    if let Some(result) = s.job.as_ref().and_then(Job::poll) {
        s.job = None;
        match result {
            Ok(addrs) => return Some(Screen::Home(Box::new(Home::new(addrs, &shared.settings)))),
            Err(e) => s.error = Some(e),
        }
    }

    page(
        ctx,
        shared,
        "Welcome back",
        "Enter your password to unlock the wallet.",
        |ui| {
            card(ui, |ui| {
                field_label(ui, "Password");
                let response = password_field(ui, &mut s.password, "");
                let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                error_line(ui, &s.error);
                let busy = s.job.is_some();
                let label = if busy { "Unlocking..." } else { "Unlock" };
                if (primary(ui, label, !busy && !s.password.is_empty()) || enter)
                    && !busy
                    && !s.password.is_empty()
                {
                    let mut password = std::mem::take(&mut s.password);
                    s.error = None;
                    s.job = Some(Job::spawn(ctx, move || {
                        let result = vault::open(&settings::vault_path(), &password)
                            .map_err(|e| e.to_string())
                            .and_then(|phrase| keys::addresses(&keys::viewing_key(&phrase)?));
                        password.zeroize();
                        result
                    }));
                }
            });
        },
    );
    None
}

// ---------------------------------------------------------------------------------------------
// Home

impl Home {
    fn new(addrs: Addresses, settings: &Settings) -> Self {
        Self {
            addrs,
            tab: Tab::Overview,
            receive: Kind::Unified,
            copied: None,
            send: SendForm::default(),
            node_input: settings.node_addr.clone(),
            reveal: Reveal::default(),
            lock: false,
        }
    }

    fn address(&self, kind: Kind) -> &str {
        match kind {
            Kind::Unified => &self.addrs.unified,
            Kind::Shielded => &self.addrs.shielded,
            Kind::Sapling => &self.addrs.sapling,
            Kind::Transparent => &self.addrs.transparent,
        }
    }
}

fn home_ui(ctx: &Context, shared: &mut Shared, home: &mut Home) {
    egui::SidePanel::left("nav")
        .exact_width(212.0)
        .resizable(false)
        .frame(Frame::new().fill(PANEL).inner_margin(Margin::same(16)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add(logo_image(shared, 40.0));
                ui.vertical(|ui| {
                    ui.add_space(2.0);
                    ui.label(RichText::new("Voltcash").strong().size(18.0));
                    ui.label(RichText::new("Wallet").color(MUTED).size(12.0));
                });
            });
            ui.add_space(18.0);
            for (tab, label) in [
                (Tab::Overview, "Overview"),
                (Tab::Receive, "Receive"),
                (Tab::Send, "Send"),
                (Tab::Settings, "Settings"),
            ] {
                let selected = home.tab == tab;
                let text = RichText::new(label).size(15.0).color(if selected {
                    Color32::WHITE
                } else {
                    TEXT
                });
                let button = egui::Button::new(text)
                    .fill(if selected {
                        ACCENT
                    } else {
                        Color32::TRANSPARENT
                    })
                    .stroke(Stroke::NONE)
                    .min_size(Vec2::new(ui.available_width(), 38.0));
                if ui.add(button).clicked() {
                    home.tab = tab;
                }
            }
            ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                if secondary(ui, "Lock wallet") {
                    home.lock = true;
                }
                ui.add_space(6.0);
                node_chip(ui, &shared.monitor.status());
            });
        });

    egui::CentralPanel::default()
        .frame(Frame::new().fill(BG).inner_margin(Margin::same(28)))
        .show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match home.tab {
                Tab::Overview => overview_ui(ui, shared, home),
                Tab::Receive => receive_ui(ui, home),
                Tab::Send => send_ui(ui, home),
                Tab::Settings => settings_ui(ctx, ui, shared, home),
            });
        });
}

fn node_chip(ui: &mut Ui, status: &NodeStatus) {
    let (color, text) = match status {
        NodeStatus::Checking => (MUTED, "Node: checking".to_owned()),
        NodeStatus::Reachable => (OK, "Node: reachable".to_owned()),
        NodeStatus::Unreachable(why) => (BAD, format!("Node: offline ({why})")),
    };
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 5.0, color);
        ui.label(RichText::new(text).size(12.0).color(MUTED));
    });
}

fn title(ui: &mut Ui, text: &str, sub: &str) {
    ui.label(RichText::new(text).size(26.0).strong());
    ui.label(RichText::new(sub).color(MUTED));
    ui.add_space(6.0);
}

fn overview_ui(ui: &mut Ui, shared: &Shared, home: &mut Home) {
    title(ui, "Overview", "Your Voltcash account at a glance.");
    card(ui, |ui| {
        ui.label(RichText::new("Balance").color(MUTED));
        ui.label(RichText::new("Not synced").size(34.0).strong());
        ui.label(
            RichText::new("This wallet can create keys and addresses today. Showing a balance needs a node that serves wallet data, which volt-node does not yet.")
                .color(MUTED),
        );
    });
    ui.columns(2, |cols| {
        card(&mut cols[0], |ui| {
            ui.label(RichText::new("Node").color(MUTED));
            ui.label(RichText::new(&shared.settings.node_addr).monospace());
            node_chip(ui, &shared.monitor.status());
            ui.label(
                RichText::new("Reachable only means the port is open.")
                    .color(MUTED)
                    .size(12.0),
            );
        });
        card(&mut cols[1], |ui| {
            ui.label(RichText::new("Your address").color(MUTED));
            ui.label(RichText::new(short(&home.addrs.unified)).monospace());
            ui.horizontal(|ui| {
                if secondary(ui, "Copy") {
                    ui.ctx().copy_text(home.addrs.unified.clone());
                    home.copied = Some(Instant::now());
                }
                if secondary(ui, "Show QR") {
                    home.tab = Tab::Receive;
                }
            });
            copied_hint(ui, home.copied);
        });
    });
}

fn short(address: &str) -> String {
    if address.len() <= 26 {
        return address.to_owned();
    }
    format!("{}...{}", &address[..14], &address[address.len() - 10..])
}

fn copied_hint(ui: &mut Ui, copied: Option<Instant>) {
    if let Some(at) = copied {
        if at.elapsed() < Duration::from_secs(2) {
            ui.label(RichText::new("Copied to clipboard").color(OK).size(12.0));
            ui.ctx().request_repaint_after(Duration::from_millis(500));
        }
    }
}

fn receive_ui(ui: &mut Ui, home: &mut Home) {
    title(ui, "Receive", "Share an address to get paid.");
    card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            for (kind, label) in [
                (Kind::Unified, "Unified"),
                (Kind::Shielded, "Shielded only"),
                (Kind::Sapling, "Sapling"),
                (Kind::Transparent, "Transparent"),
            ] {
                ui.selectable_value(&mut home.receive, kind, label);
            }
        });
        let blurb = match home.receive {
            Kind::Unified => "Works for every kind of sender. Funds sent privately arrive shielded; transparent senders are paid into your transparent receiver.",
            Kind::Shielded => "Orchard and Sapling receivers only. Nothing sent here ever touches a transparent address.",
            Kind::Sapling => "For wallets that predate unified addresses.",
            Kind::Transparent => "Visible on the public ledger, like Bitcoin. Use a shielded address when you want privacy.",
        };
        ui.label(RichText::new(blurb).color(MUTED));
        if home.receive == Kind::Transparent {
            notice(
                ui,
                WARN,
                "Transparent payments reveal the amount, sender and receiver to everyone.",
            );
        }
        ui.add_space(4.0);
        let address = home.address(home.receive).to_owned();
        ui.horizontal_top(|ui| {
            qr_code(ui, &address, 200.0);
            ui.vertical(|ui| {
                ui.add(
                    egui::Label::new(RichText::new(&address).monospace().size(13.0))
                        .wrap()
                        .selectable(true),
                );
                ui.horizontal(|ui| {
                    if primary(ui, "Copy address", true) {
                        ui.ctx().copy_text(address.clone());
                        home.copied = Some(Instant::now());
                    }
                    copied_hint(ui, home.copied);
                });
            });
        });
    });
}

fn qr_code(ui: &mut Ui, data: &str, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(8), Color32::WHITE);
    let Ok(code) = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
    else {
        return;
    };
    let modules = code.width();
    let quiet = 2.0;
    let cell = size / (modules as f32 + 2.0 * quiet);
    for (i, color) in code.to_colors().into_iter().enumerate() {
        if color == qrcode::Color::Dark {
            let (x, y) = ((i % modules) as f32, (i / modules) as f32);
            let min = rect.min + Vec2::new((x + quiet) * cell, (y + quiet) * cell);
            painter.rect_filled(
                egui::Rect::from_min_size(min, Vec2::splat(cell.ceil())),
                CornerRadius::ZERO,
                Color32::BLACK,
            );
        }
    }
}

fn send_ui(ui: &mut Ui, home: &mut Home) {
    title(ui, "Send", "Pay a Voltcash address.");
    let recipient = keys::check_recipient(&home.send.to);
    let amount = parse_volt(&home.send.amount);
    card(ui, |ui| {
        field_label(ui, "Recipient");
        ui.add(
            egui::TextEdit::singleline(&mut home.send.to)
                .hint_text("volt1... or Vo... or volts1...")
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        if !home.send.to.trim().is_empty() {
            match &recipient {
                Ok(RecipientKind::Transparent) => {
                    ui.label(
                        RichText::new("Transparent address: this payment will be public.")
                            .color(WARN),
                    );
                }
                Ok(_) => {
                    ui.label(RichText::new("Valid Voltcash address.").color(OK));
                }
                Err(e) => {
                    ui.label(RichText::new(e.as_str()).color(BAD));
                }
            }
        }
        field_label(ui, "Amount (VOLT)");
        ui.add(
            egui::TextEdit::singleline(&mut home.send.amount)
                .hint_text("0.00000000")
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        if !home.send.amount.trim().is_empty() {
            if let Err(e) = &amount {
                ui.label(RichText::new(*e).color(BAD));
            }
        }
        let can_memo = matches!(
            recipient,
            Ok(RecipientKind::Unified | RecipientKind::Sapling)
        );
        field_label(ui, "Memo (shielded recipients only, optional)");
        ui.add_enabled(
            can_memo,
            egui::TextEdit::multiline(&mut home.send.memo)
                .desired_rows(2)
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        if let Ok(zats) = amount {
            ui.label(
                RichText::new(format!(
                    "Network fee: {} VOLT (smallest fee tier). Total: {} VOLT",
                    format_volt(MIN_FEE_ZATS),
                    format_volt(zats.saturating_add(MIN_FEE_ZATS)),
                ))
                .color(MUTED),
            );
        }
    });
    notice(
        ui,
        WARN,
        "Sending is switched off. It needs this wallet to scan the chain for your notes, and volt-node does not serve that data yet.",
    );
    primary(ui, "Send", false);
}

fn settings_ui(ctx: &Context, ui: &mut Ui, shared: &mut Shared, home: &mut Home) {
    title(ui, "Settings", "Node connection, backup and about.");

    card(ui, |ui| {
        ui.label(RichText::new("Node").strong().size(17.0));
        field_label(ui, "volt-node address");
        ui.add(
            egui::TextEdit::singleline(&mut home.node_input)
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        ui.horizontal(|ui| {
            let changed = home.node_input.trim() != shared.settings.node_addr;
            if primary(ui, "Save", changed) {
                shared.settings.node_addr = home.node_input.trim().to_owned();
                match shared.settings.save() {
                    Ok(()) => shared.monitor.set_addr(shared.settings.node_addr.clone()),
                    Err(e) => home.reveal.error = Some(format!("could not save settings: {e}")),
                }
            }
            if secondary(ui, "Use default") {
                home.node_input = settings::DEFAULT_NODE_ADDR.to_owned();
            }
        });
    });

    card(ui, |ui| {
        ui.label(RichText::new("Recovery phrase").strong().size(17.0));
        ui.label(
            RichText::new("Enter your password to show the phrase again. Make sure nobody can see your screen.")
                .color(MUTED),
        );
        if let Some(result) = home.reveal.job.as_ref().and_then(Job::poll) {
            home.reveal.job = None;
            match result {
                Ok(phrase) => {
                    home.reveal.shown = Some(phrase);
                    home.reveal.error = None;
                }
                Err(e) => home.reveal.error = Some(e),
            }
        }
        if let Some(phrase) = &home.reveal.shown {
            egui::Grid::new("shown-phrase")
                .num_columns(4)
                .spacing([18.0, 8.0])
                .show(ui, |ui| {
                    for (i, word) in phrase.split(' ').enumerate() {
                        ui.label(RichText::new(format!("{:>2}. {word}", i + 1)).monospace());
                        if i % 4 == 3 {
                            ui.end_row();
                        }
                    }
                });
            if secondary(ui, "Hide") {
                home.reveal = Reveal::default();
            }
        } else {
            password_field(ui, &mut home.reveal.password, "password");
            error_line(ui, &home.reveal.error);
            let busy = home.reveal.job.is_some();
            if primary(
                ui,
                if busy { "Checking..." } else { "Show phrase" },
                !busy && !home.reveal.password.is_empty(),
            ) {
                let mut password = std::mem::take(&mut home.reveal.password);
                home.reveal.job = Some(Job::spawn(ctx, move || {
                    let result =
                        vault::open(&settings::vault_path(), &password).map_err(|e| e.to_string());
                    password.zeroize();
                    result
                }));
            }
        }
    });

    card(ui, |ui| {
        ui.label(RichText::new("About").strong().size(17.0));
        for (k, v) in [
            ("Wallet file", settings::vault_path().display().to_string()),
            (
                "Keys",
                "ZIP 32 via librustzcash (zcash_keys); Sapling, Orchard and transparent".to_owned(),
            ),
            (
                "Coin type",
                "22083 (never shared with a Zcash wallet's keys)".to_owned(),
            ),
            ("Address prefixes", "volt1 / volts1 / Vo".to_owned()),
            ("Version", env!("CARGO_PKG_VERSION").to_owned()),
        ] {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(k).color(MUTED));
                ui.label(RichText::new(v).monospace().size(13.0));
            });
        }
    });
}
