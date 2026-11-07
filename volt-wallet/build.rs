// Embeds the Voltcash logo as the Windows executable's icon.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/logo.ico");
        res.set("ProductName", "Voltcash Wallet");
        res.set("FileDescription", "Voltcash Wallet");
        if let Err(e) = res.compile() {
            // A missing resource compiler must not stop the wallet from building.
            println!("cargo:warning=could not embed the exe icon: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/logo.ico");
}
