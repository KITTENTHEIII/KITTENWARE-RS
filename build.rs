use std::env;
use std::io;
use winresource::WindowsResource;

fn main() -> io::Result<()> {
    // Only compile the copy for Windows targets
    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.compile()?;
    }
    Ok(())
}
