//! The Voltcash Core UI: wallet, node and miner.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Color32, ColorImage, Context, CornerRadius, Frame, Layout, Margin, RichText,
    Sense, Stroke, TextureHandle, TextureOptions, Ui, Vec2,
};
use rand::seq::SliceRandom;
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{self, Account, Addresses, RecipientKind};
use crate::localnode::{self, LocalNode};
use crate::network::{format_volt, parse_volt};
use crate::node::{NodeMonitor, NodeStatus};
use crate::pay;
use crate::rpc::{self, BalanceMonitor};
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

/// The fee tiers `volt-core` charges, in zats (`fee.rs`). Anything touching a shielded pool pays
/// the shielded tier; only transparent-to-transparent pays the lower one.
/// What a payment normally costs. A payment that only touches public coins costs half as much;
/// the exact fee is worked out when the payment is built.
const TYPICAL_FEE_ZATS: u64 = 20_000;

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
    job: Option<Job<Result<Account, String>>>,
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
    job: Option<Job<Result<Account, String>>>,
    error: Option<String>,
}

#[derive(Default)]
struct Unlock {
    password: String,
    job: Option<Job<Result<Account, String>>>,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Receive,
    Send,
    Node,
    Explorer,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Shielded,
    Transparent,
}

struct Home {
    addrs: Addresses,
    balance: BalanceMonitor,
    rpc_addr: String,
    explorer: Explorer,
    data_dir_input: String,
    args_input: String,
    tab: Tab,
    receive: Kind,
    copied: Option<Instant>,
    send: SendForm,
    node_input: String,
    reveal: Reveal,
    exe_input: String,
    mine: bool,
    node_msg: Option<(bool, String)>,
    backup: Option<Job<Result<String, String>>>,
    backup_msg: Option<(bool, String)>,
    lock: bool,
}

#[derive(Default)]
struct SendForm {
    to: String,
    amount: String,
    memo: String,
    password: String,
    job: Option<Job<Result<String, String>>>,
    result: Option<(bool, String)>,
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
    local: LocalNode,
}

pub struct VoltCore {
    shared: Shared,
    screen: Screen,
}

impl VoltCore {
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
                local: LocalNode::default(),
            },
            screen,
        }
    }
}

impl eframe::App for VoltCore {
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
        "Voltcash Core",
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
            Ok(account) => {
                return Some(Screen::Home(Box::new(Home::new(
                    ctx,
                    account,
                    &shared.settings,
                ))))
            }
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

fn finish_create(phrase: &str, password: &str) -> Result<Account, String> {
    let account = keys::account(phrase)?;
    vault::create(&settings::vault_path(), phrase, password).map_err(|e| e.to_string())?;
    Ok(account)
}

fn restore_ui(ctx: &Context, shared: &Shared, s: &mut Restore) -> Option<Screen> {
    let mut next = None;

    if let Some(result) = s.job.as_ref().and_then(Job::poll) {
        s.job = None;
        match result {
            Ok(account) => {
                return Some(Screen::Home(Box::new(Home::new(
                    ctx,
                    account,
                    &shared.settings,
                ))))
            }
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
            Ok(account) => {
                return Some(Screen::Home(Box::new(Home::new(
                    ctx,
                    account,
                    &shared.settings,
                ))))
            }
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
                            .and_then(|phrase| keys::account(&phrase));
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
    fn new(ctx: &Context, account: Account, settings: &Settings) -> Self {
        let addrs = account.addrs;
        let balance = BalanceMonitor::start(
            settings.rpc_addr.clone(),
            addrs.transparent.clone(),
            account
                .ufvk
                .sapling()
                .expect("every Voltcash account has a Sapling component"),
            Some(settings::data_dir().join("scan.cache")),
            ctx.clone(),
        );
        Self {
            addrs,
            balance,
            rpc_addr: settings.rpc_addr.clone(),
            explorer: Explorer::default(),
            data_dir_input: settings.node_data_dir.clone(),
            args_input: settings.node_args.clone(),
            tab: Tab::Overview,
            receive: Kind::Shielded,
            copied: None,
            send: SendForm::default(),
            node_input: settings.node_addr.clone(),
            reveal: Reveal::default(),
            exe_input: settings.node_exe.clone(),
            mine: false,
            node_msg: None,
            backup: None,
            backup_msg: None,
            lock: false,
        }
    }

    fn address(&self, kind: Kind) -> &str {
        match kind {
            Kind::Shielded => &self.addrs.shielded,
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
                    ui.label(
                        RichText::new("Wallet, node and miner")
                            .color(MUTED)
                            .size(12.0),
                    );
                });
            });
            ui.add_space(18.0);
            for (tab, label) in [
                (Tab::Overview, "Overview"),
                (Tab::Receive, "Receive"),
                (Tab::Send, "Send"),
                (Tab::Node, "Node & mining"),
                (Tab::Explorer, "Explorer"),
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
                Tab::Node => node_ui(ui, shared, home),
                Tab::Explorer => explorer_ui(ui, home),
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
        match home.balance.total() {
            None => {
                ui.label(RichText::new("Checking...").size(34.0).strong());
            }
            Some(Ok(zats)) => {
                ui.label(
                    RichText::new(format!("{} VOLT", format_volt(zats)))
                        .size(34.0)
                        .strong(),
                );
                ui.label(
                    RichText::new("One balance. When you pay, the wallet spends your private coins first and only uses public ones if it has to, and it keeps your change private. Only you can see the private part: this wallet finds it by scanning the chain with its viewing key.")
                        .color(MUTED)
                        .size(12.0),
                );
            }
            Some(Err(e)) => {
                ui.label(RichText::new("Not connected").size(34.0).strong());
                ui.label(RichText::new(format!("Could not read the balance: {e}.")).color(BAD));
                ui.label(
                    RichText::new("Start volt-node with --rpc (Node & mining > Start node does this), or fix the node address.")
                        .color(MUTED),
                );
            }
        }
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
            ui.label(RichText::new(short(&home.addrs.shielded)).monospace());
            ui.horizontal(|ui| {
                if secondary(ui, "Copy") {
                    ui.ctx().copy_text(home.addrs.shielded.clone());
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
                (Kind::Shielded, "Shielded (z)"),
                (Kind::Transparent, "Transparent (t)"),
            ] {
                ui.selectable_value(&mut home.receive, kind, label);
            }
        });
        let blurb = match home.receive {
            Kind::Shielded => "Private. Amount, sender and receiver stay hidden, and nothing sent here ever touches a transparent address.",
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
    title(ui, "Send", "Pay any Voltcash address from your balance.");
    let total = home.balance.total().and_then(Result::ok);
    if let Some(total) = total {
        ui.label(RichText::new(format!("Balance {} VOLT", format_volt(total))).color(MUTED));
    }

    let recipient = keys::check_recipient(&home.send.to);
    let amount = parse_volt(&home.send.amount);
    let private_recipient = matches!(
        recipient,
        Ok(RecipientKind::Unified | RecipientKind::Sapling)
    );
    card(ui, |ui| {
        field_label(ui, "Recipient");
        ui.add(
            egui::TextEdit::singleline(&mut home.send.to)
                .hint_text("z1... (private) or tv... (public)")
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        if !home.send.to.trim().is_empty() {
            match &recipient {
                Ok(RecipientKind::Transparent) => {
                    ui.label(
                        RichText::new(
                            "Public address: the amount and this address will be visible to everyone.",
                        )
                        .color(WARN),
                    );
                }
                Ok(_) => {
                    ui.label(
                        RichText::new("Private address: the amount and the recipient stay hidden.")
                            .color(OK),
                    );
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
        field_label(ui, "Memo (private; only for private recipients, optional)");
        ui.add_enabled(
            private_recipient,
            egui::TextEdit::multiline(&mut home.send.memo)
                .desired_rows(2)
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        if let Ok(zats) = amount {
            ui.label(
                RichText::new(format!(
                    "Network fee: about {} VOLT. Total: about {} VOLT",
                    format_volt(TYPICAL_FEE_ZATS),
                    format_volt(zats.saturating_add(TYPICAL_FEE_ZATS)),
                ))
                .color(MUTED),
            );
        }
    });

    notice(
        ui,
        OK,
        "The wallet builds the payment and its zero-knowledge proof on your computer and picks what to spend: private coins first, then public ones if needed. Using both in one payment links them on the chain. Change comes back to your private balance. Proving takes a few seconds.",
    );
    field_label(ui, "Wallet password (to sign this payment)");
    password_field(ui, &mut home.send.password, "your wallet password");

    if let Some(result) = home.send.job.as_ref().and_then(Job::poll) {
        home.send.job = None;
        home.balance.refresh();
        home.send.result = Some(match result {
            Ok(txid) => {
                home.send.to.clear();
                home.send.amount.clear();
                home.send.memo.clear();
                (
                    true,
                    format!("Sent. Transaction {txid} (open it in the Explorer)."),
                )
            }
            Err(e) => (false, format!("Not sent: {e}")),
        });
    }
    let busy = home.send.job.is_some();
    if busy {
        ui.ctx().request_repaint_after(Duration::from_millis(300));
    }

    let funds = match (&amount, total) {
        (Ok(zats), Some(have)) if zats.saturating_add(TYPICAL_FEE_ZATS) > have => {
            Some("The amount plus the fee is more than your balance.")
        }
        _ => None,
    };
    if let (Some(text), true) = (funds, !home.send.amount.trim().is_empty()) {
        ui.label(RichText::new(text).color(BAD));
    }
    let ready = !busy
        && recipient.is_ok()
        && amount.is_ok()
        && total.is_some()
        && funds.is_none()
        && !home.send.password.is_empty();
    let label = if busy {
        "Proving and sending..."
    } else {
        "Send"
    };
    if primary(ui, label, ready) {
        if let Ok(zats) = amount {
            let service = home.rpc_addr.clone();
            let scanner = home.balance.scanner();
            let t_address = home.addrs.transparent.clone();
            let payment = pay::Payment {
                to: home.send.to.trim().to_owned(),
                zats,
                memo: home.send.memo.clone(),
            };
            let mut password = std::mem::take(&mut home.send.password);
            let ctx = ui.ctx().clone();
            home.send.result = None;
            home.send.job = Some(Job::spawn(&ctx, move || {
                let result = pay_now(&service, &scanner, &t_address, &password, &payment);
                password.zeroize();
                result
            }));
        }
    }
    status_line(ui, &home.send.result);
}

/// Signs, proves and sends one payment. Runs on a background thread.
fn pay_now(
    service: &str,
    scanner: &std::sync::Arc<std::sync::Mutex<crate::chain::Scanner>>,
    t_address: &str,
    password: &str,
    payment: &pay::Payment,
) -> Result<String, String> {
    // The spending key exists only for the length of this call.
    let phrase = vault::open(&settings::vault_path(), password).map_err(|e| e.to_string())?;
    let usk = keys::spending_key(&phrase)?;
    drop(phrase);

    crate::chain::sync(scanner, service)?;
    let utxos = rpc::utxos(service, t_address)?;
    let built = {
        let scanner = scanner.lock().expect("scanner lock");
        pay::build(&usk, &scanner, &utxos, payment)?
    };
    let txid = rpc::send_raw(service, &built.raw)?;
    // A local devnet node mines your payment right away. On a real network this call does nothing
    // useful, and the payment waits for someone else's block.
    let _ = rpc::mine(service, 2, Some(&crate::network::dev_sink_address()));
    Ok(txid)
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

    backup_card(ui, home);

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
            (
                "Address prefixes",
                "z1 (shielded) / tv (transparent)".to_owned(),
            ),
            ("Version", env!("CARGO_PKG_VERSION").to_owned()),
        ] {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(k).color(MUTED));
                ui.label(RichText::new(v).monospace().size(13.0));
            });
        }
    });
}

fn status_line(ui: &mut Ui, message: &Option<(bool, String)>) {
    if let Some((ok, text)) = message {
        ui.label(RichText::new(text).color(if *ok { OK } else { BAD }));
    }
}

fn node_ui(ui: &mut Ui, shared: &mut Shared, home: &mut Home) {
    title(
        ui,
        "Node & mining",
        "Run the Voltcash node and miner from this app.",
    );
    local_node_card(ui, shared, home);
    card(ui, |ui| {
        ui.label(RichText::new("Chain").strong().size(17.0));
        match home.balance.info() {
            None => {
                ui.label(
                    RichText::new(
                        "No node answering on the wallet service address. Start the node above.",
                    )
                    .color(MUTED),
                );
            }
            Some(info) => {
                egui::Grid::new("chain-info")
                    .num_columns(2)
                    .spacing([24.0, 8.0])
                    .show(ui, |ui| {
                        for (label, value) in [
                            ("Blocks accepted", info.accepted),
                            ("Blocks in the DAG", info.dag),
                            ("Unspent outputs", info.utxos),
                            ("Waiting in the mempool", info.mempool),
                            ("Peers", info.peers),
                        ] {
                            ui.label(RichText::new(label).color(MUTED));
                            ui.label(RichText::new(value.to_string()).monospace());
                            ui.end_row();
                        }
                    });
            }
        }
        ui.label(
            RichText::new(format!("Listening on {}", shared.settings.node_addr))
                .color(MUTED)
                .size(12.0),
        );
    });
}

// ---------------------------------------------------------------------------------------------
// Explorer

/// What the explorer is showing below the block list.
enum Found {
    Block(rpc::BlockDetail),
    Tx(rpc::TxDetail),
    Address { address: String, zats: u64 },
}

#[derive(Default)]
struct Explorer {
    query: String,
    found: Option<Found>,
    job: Option<Job<Result<Found, String>>>,
    error: Option<String>,
}

fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit())
}

fn ago(timestamp_ms: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let secs = now.saturating_sub(timestamp_ms) / 1000;
    match secs {
        0..=59 => format!("{secs} s ago"),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

fn kind_label(kind: &str) -> String {
    match kind {
        "t-t" => "t-t transparent",
        "t-z" => "t-z shielding",
        "z-z" => "z-z shielded",
        "z-t" => "z-t unshielding",
        "mixed" => "mixed public and private",
        _ => "other",
    }
    .to_owned()
}

fn kind_color(kind: &str) -> Color32 {
    match kind {
        "z-z" => OK,
        "t-z" | "z-t" | "mixed" => WARN,
        _ => MUTED,
    }
}

fn kind_note(kind: &str) -> &'static str {
    match kind {
        "t-t" => "A public payment between two public addresses.",
        "t-z" => "Public coins moved into the shielded pool.",
        "z-z" => "A payment inside the shielded pool; no public address is involved.",
        "z-t" => "Private coins moved out to a public address.",
        "mixed" => "Spent private notes and public coins together in one payment.",
        _ => "Unclassified.",
    }
}

fn start_lookup(ui: &Ui, home: &mut Home, query: String) {
    let query = query.trim().to_owned();
    let service = home.rpc_addr.clone();
    home.explorer.error = None;
    if is_hash(&query) {
        home.explorer.job = Some(Job::spawn(ui.ctx(), move || {
            // A 64-character hash is a block or a transaction: try blocks first.
            let hash = query.to_ascii_lowercase();
            rpc::block(&service, &hash)
                .map(Found::Block)
                .or_else(|_| rpc::tx(&service, &hash).map(Found::Tx))
                .map_err(|_| "no block or transaction with that id".to_owned())
        }));
    } else if query.starts_with("tv") {
        home.explorer.job = Some(Job::spawn(ui.ctx(), move || {
            rpc::balance(&service, &query).map(|zats| Found::Address {
                address: query,
                zats,
            })
        }));
    } else {
        home.explorer.error =
            Some("Enter a block or transaction id (64 hex characters) or a tv... address.".into());
    }
}

fn explorer_ui(ui: &mut Ui, home: &mut Home) {
    title(
        ui,
        "Explorer",
        "Browse the blocks of the node this app is connected to.",
    );

    if let Some(result) = home.explorer.job.as_ref().and_then(Job::poll) {
        home.explorer.job = None;
        match result {
            Ok(found) => home.explorer.found = Some(found),
            Err(e) => {
                home.explorer.found = None;
                home.explorer.error = Some(e);
            }
        }
    }

    card(ui, |ui| {
        ui.horizontal(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut home.explorer.query)
                    .hint_text("Block hash, transaction id or tv... address")
                    .desired_width(ui.available_width() - 110.0)
                    .margin(Margin::symmetric(10, 8)),
            );
            let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let busy = home.explorer.job.is_some();
            let go = ui
                .add_enabled(
                    !busy,
                    egui::Button::new("Search").min_size(Vec2::new(90.0, 34.0)),
                )
                .clicked();
            if (go || enter) && !busy && !home.explorer.query.trim().is_empty() {
                let query = home.explorer.query.clone();
                start_lookup(ui, home, query);
            }
        });
        error_line(ui, &home.explorer.error);
    });

    let mut open: Option<String> = None;
    let mut close = false;
    match &home.explorer.found {
        Some(Found::Address { address, zats }) => card(ui, |ui| {
            ui.label(RichText::new("Address").strong().size(17.0));
            ui.add(egui::Label::new(RichText::new(address).monospace()).selectable(true));
            ui.label(RichText::new(format!("{} VOLT unspent", format_volt(*zats))).size(20.0));
            if secondary(ui, "Close") {
                close = true;
            }
        }),
        Some(Found::Tx(t)) => card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Transaction").strong().size(17.0));
                ui.label(
                    RichText::new(kind_label(&t.kind))
                        .color(kind_color(&t.kind))
                        .strong(),
                );
            });
            ui.add(
                egui::Label::new(RichText::new(&t.txid).monospace().size(12.0)).selectable(true),
            );
            egui::Grid::new("tx-detail")
                .num_columns(2)
                .spacing([24.0, 6.0])
                .show(ui, |ui| {
                    let direction = kind_note(&t.kind);
                    let pool = match t.pool_out {
                        0 => "no change".to_owned(),
                        v if v < 0 => format!("{} VOLT in", format_volt(v.unsigned_abs())),
                        v => format!("{} VOLT out", format_volt(v.unsigned_abs())),
                    };
                    for (label, value) in [
                        ("What it does", direction.to_owned()),
                        ("Fee", format!("{} VOLT", format_volt(t.fee))),
                        ("Public inputs spent", t.inputs.to_string()),
                        ("Shielded notes spent", t.nullifiers.to_string()),
                        ("Shielded pool", pool),
                    ] {
                        ui.label(RichText::new(label).color(MUTED));
                        ui.label(RichText::new(value));
                        ui.end_row();
                    }
                });
            if !t.outputs.is_empty() {
                ui.label(RichText::new("Public outputs").color(MUTED));
                for (address, zats) in &t.outputs {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(short(address)).monospace());
                        ui.label(format!("{} VOLT", format_volt(*zats)));
                    });
                }
            }
            if !t.notes.is_empty() {
                ui.label(RichText::new("Shielded notes created").color(MUTED));
                for note in &t.notes {
                    ui.label(if note == "hidden" {
                        "a shielded note (recipient and amount are encrypted)".to_owned()
                    } else {
                        format!("a note of {note} (devnet: readable)")
                    });
                }
            }
            ui.horizontal(|ui| {
                ui.label(RichText::new("In block").color(MUTED));
                if ui
                    .add(egui::Button::new(RichText::new(short(&t.block)).monospace()).frame(false))
                    .clicked()
                {
                    open = Some(t.block.clone());
                }
            });
            if secondary(ui, "Close") {
                close = true;
            }
        }),
        Some(Found::Block(b)) => {
            card(ui, |ui| {
                ui.label(
                    RichText::new(format!("Block #{}", b.index))
                        .strong()
                        .size(17.0),
                );
                ui.add(
                    egui::Label::new(RichText::new(&b.hash).monospace().size(12.0))
                        .selectable(true),
                );
                egui::Grid::new("block-detail")
                    .num_columns(2)
                    .spacing([24.0, 6.0])
                    .show(ui, |ui| {
                        for (label, value) in [
                            ("Time", ago(b.timestamp_ms)),
                            ("Difficulty bits", format!("{:#010x}", b.bits)),
                            ("Nonce", b.nonce.to_string()),
                            ("Transactions", b.txs.len().to_string()),
                            (
                                "Locked as liquidity",
                                format!("{} VOLT", format_volt(b.pol)),
                            ),
                        ] {
                            ui.label(RichText::new(label).color(MUTED));
                            ui.label(RichText::new(value).monospace());
                            ui.end_row();
                        }
                    });
                ui.label(RichText::new("Parents").color(MUTED));
                if b.parents.is_empty() {
                    ui.label("none (genesis)");
                }
                for parent in &b.parents {
                    if ui
                        .add(
                            egui::Button::new(RichText::new(short(parent)).monospace())
                                .frame(false),
                        )
                        .clicked()
                    {
                        open = Some(parent.clone());
                    }
                }
                ui.label(RichText::new("Paid to miners").color(MUTED));
                for (address, zats) in &b.payouts {
                    ui.horizontal(|ui| {
                        if ui
                            .add(
                                egui::Button::new(RichText::new(short(address)).monospace())
                                    .frame(false),
                            )
                            .clicked()
                        {
                            open = Some(address.clone());
                        }
                        ui.label(format!("{} VOLT", format_volt(*zats)));
                    });
                }
                if !b.txs.is_empty() {
                    ui.label(RichText::new("Transactions").color(MUTED));
                    for (txid, kind) in &b.txs {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(kind_label(kind)).color(kind_color(kind)));
                            if ui
                                .add(
                                    egui::Button::new(RichText::new(short(txid)).monospace())
                                        .frame(false),
                                )
                                .clicked()
                            {
                                open = Some(txid.clone());
                            }
                        });
                    }
                }
                if secondary(ui, "Close") {
                    close = true;
                }
            });
        }
        None => {}
    }
    if close {
        home.explorer.found = None;
    }

    let (total, rows) = home.balance.recent();
    card(ui, |ui| {
        ui.label(
            RichText::new(format!("Latest blocks ({total} total)"))
                .strong()
                .size(17.0),
        );
        if rows.is_empty() {
            ui.label(
                RichText::new("No blocks to show. Start the node on the Node & mining tab, or check the node address in Settings.")
                    .color(MUTED),
            );
            return;
        }
        egui::Grid::new("blocks")
            .num_columns(5)
            .spacing([22.0, 8.0])
            .striped(true)
            .show(ui, |ui| {
                for h in ["Block", "Hash", "Time", "Txs", "Reward"] {
                    ui.label(RichText::new(h).color(MUTED).size(12.0));
                }
                ui.end_row();
                for row in &rows {
                    ui.label(RichText::new(format!("#{}", row.index)).monospace());
                    if ui
                        .add(
                            egui::Button::new(RichText::new(short(&row.hash)).monospace())
                                .frame(false),
                        )
                        .clicked()
                    {
                        open = Some(row.hash.clone());
                    }
                    ui.label(ago(row.timestamp_ms));
                    ui.label(row.txs.to_string());
                    ui.label(format!("{} VOLT", format_volt(row.reward)));
                    ui.end_row();
                }
            });
    });

    if let Some(target) = open {
        home.explorer.query = target.clone();
        start_lookup(ui, home, target);
    }
    if home.explorer.job.is_some() {
        ui.ctx().request_repaint_after(Duration::from_millis(200));
    }
}

/// Starts the local node. If another node already holds the configured address, starts a second
/// one beside it, on its own ports and chain folder, and peers with the first.
fn start_local_node(shared: &mut Shared, home: &mut Home) {
    shared.settings.node_exe = home.exe_input.trim().to_owned();
    shared.settings.node_data_dir = home.data_dir_input.trim().to_owned();
    shared.settings.node_args = home.args_input.trim().to_owned();
    let mut data_dir = if shared.settings.node_data_dir.is_empty() {
        localnode::node_data_dir()
    } else {
        std::path::PathBuf::from(&shared.settings.node_data_dir)
    };
    let mut listen = shared.settings.node_addr.clone();
    let mut service = shared.settings.rpc_addr.clone();

    let joining = shared.monitor.status() == NodeStatus::Reachable;
    let first = listen.clone();
    if joining {
        let Some((peer_port, rpc_port)) = localnode::free_port_pair() else {
            home.node_msg = Some((false, "No free local ports for a second node.".to_owned()));
            return;
        };
        if !shared
            .settings
            .peer_seeds
            .split_whitespace()
            .any(|s| s == first)
        {
            shared.settings.peer_seeds = format!("{} {first}", shared.settings.peer_seeds)
                .trim()
                .to_owned();
        }
        listen = format!("127.0.0.1:{peer_port}");
        service = format!("127.0.0.1:{rpc_port}");
        // Two nodes cannot share one chain folder, so a second node always gets its own.
        data_dir = localnode::node_data_dir();
    }

    let mut extra = shared.settings.node_args.clone();
    for seed in shared.settings.peer_seeds.split_whitespace() {
        if seed != listen {
            extra.push_str(&format!(" --seed {seed}"));
        }
    }
    if joining {
        // Each node on this machine needs its own placeholder miner addresses.
        let port: u32 = listen
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(2);
        extra.push_str(&format!(" --name {}", port % 200 + 1));
    }

    let Some(exe) = localnode::find_node_exe(&shared.settings.node_exe) else {
        home.node_msg = Some((
            false,
            "volt-node was not found. Build it (cargo build --release -p volt-node) or enter its path."
                .to_owned(),
        ));
        return;
    };
    home.node_msg = Some(
        match shared.local.start(
            &exe,
            &data_dir,
            &listen,
            &service,
            home.mine,
            &home.addrs.transparent,
            &extra,
        ) {
            Ok(()) => {
                if joining {
                    shared.settings.node_addr = listen.clone();
                    shared.settings.rpc_addr = service.clone();
                }
                let _ = shared.settings.save();
                shared.monitor.set_addr(shared.settings.node_addr.clone());
                home.rpc_addr = shared.settings.rpc_addr.clone();
                home.node_input = shared.settings.node_addr.clone();
                home.balance.set_service(home.rpc_addr.clone());
                if joining {
                    (
                        true,
                        format!(
                            "Started a second node on {listen}, peered with the one on {first}."
                        ),
                    )
                } else {
                    (true, format!("Started {}", exe.display()))
                }
            }
            Err(e) => (false, e),
        },
    );
}

fn local_node_card(ui: &mut Ui, shared: &mut Shared, home: &mut Home) {
    let running = shared.local.is_running();
    let mining = shared.local.is_mining();
    if let Some(why) = shared.local.take_exit() {
        home.node_msg = Some((false, why));
    }
    if running {
        // Notice if the node exits on its own.
        ui.ctx().request_repaint_after(Duration::from_secs(1));
    }
    card(ui, |ui| {
        ui.label(RichText::new("Node and miner").strong().size(17.0));
        ui.label(
            RichText::new("Voltcash Core runs the node and the miner on this computer, on localhost only for now (nothing outside this machine can connect). This is a development node: it uses a Blake2b stand-in for RandomX and a devnet genesis.")
                .color(MUTED),
        );
        let (color, text) = match (running, mining) {
            (true, true) => (OK, "Running and mining to this wallet"),
            (true, false) => (OK, "Running (not mining)"),
            (false, _) => (MUTED, "Stopped"),
        };
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
            ui.painter().circle_filled(rect.center(), 5.0, color);
            ui.label(text);
        });
        field_label(
            ui,
            "volt-node program (leave empty to find it automatically)",
        );
        ui.add_enabled(
            !running,
            egui::TextEdit::singleline(&mut home.exe_input)
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        field_label(ui, "Chain folder (leave empty for this wallet's own)");
        ui.add_enabled(
            !running,
            egui::TextEdit::singleline(&mut home.data_dir_input)
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        field_label(ui, "Extra node options (for example --economics faucet)");
        ui.add_enabled(
            !running,
            egui::TextEdit::singleline(&mut home.args_input)
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(10, 8)),
        );
        ui.add_enabled(
            !running,
            egui::Checkbox::new(&mut home.mine, "Mine to this wallet's transparent address"),
        );
        ui.label(
            RichText::new("Mined coins are transparent and become spendable after 100 blocks.")
                .color(MUTED)
                .size(12.0),
        );
        ui.horizontal(|ui| {
            if running {
                if secondary(ui, "Stop node") {
                    shared.local.stop();
                    home.node_msg = Some((true, "Node stopped.".into()));
                }
            } else if primary(ui, "Start node", true) {
                start_local_node(shared, home);
            }
        });
        status_line(ui, &home.node_msg);
        ui.label(
            RichText::new(format!(
                "Log: {}",
                if shared.settings.node_data_dir.is_empty() {
                    localnode::node_data_dir()
                } else {
                    std::path::PathBuf::from(&shared.settings.node_data_dir)
                }
                .join("node.log")
                .display()
            ))
            .color(MUTED)
            .size(12.0),
        );
    });
}

fn backup_card(ui: &mut Ui, home: &mut Home) {
    if let Some(result) = home.backup.as_ref().and_then(Job::poll) {
        home.backup = None;
        home.backup_msg = Some(match result {
            Ok(path) => (true, format!("Saved to {path}")),
            Err(e) => (false, e),
        });
    }
    card(ui, |ui| {
        ui.label(RichText::new("Backup").strong().size(17.0));
        ui.label(
            RichText::new("The wallet file is already encrypted with your password. Keep a copy somewhere safe; your recovery phrase stays the real backup. To use a copy, put it in the wallet folder as wallet.vault.")
                .color(MUTED),
        );
        ui.horizontal(|ui| {
            let busy = home.backup.is_some();
            if ui
                .add_enabled(!busy, egui::Button::new("Save encrypted copy..."))
                .clicked()
            {
                let ctx = ui.ctx().clone();
                home.backup = Some(Job::spawn(&ctx, || {
                    let Some(target) = rfd::FileDialog::new()
                        .set_title("Save wallet backup")
                        .set_file_name("voltcash-wallet-backup.vault")
                        .save_file()
                    else {
                        return Err("Cancelled.".to_owned());
                    };
                    std::fs::copy(settings::vault_path(), &target)
                        .map(|_| target.display().to_string())
                        .map_err(|e| format!("could not save the backup: {e}"))
                }));
            }
            if secondary(ui, "Open wallet folder") {
                let _ = std::process::Command::new("explorer")
                    .arg(settings::data_dir())
                    .spawn();
            }
        });
        status_line(ui, &home.backup_msg);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn both_kinds_of_address_are_valid_recipients() {
        let a = keys::addresses(&keys::viewing_key(PHRASE).unwrap()).unwrap();
        assert_eq!(
            keys::check_recipient(&a.shielded),
            Ok(RecipientKind::Unified)
        );
        assert_eq!(
            keys::check_recipient(&a.transparent),
            Ok(RecipientKind::Transparent)
        );
    }
}
