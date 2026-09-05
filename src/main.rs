use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

// ANSI colours

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

const LOGO: &str = r#"
 _  _______ _______ _______ ______ _   ___          __     _____  ______      _____   _____
| |/ /_   _|__   __|__   __|  ____| \ | \ \        / /\   |  __ \|  ____|    |  __ \ / ____|
| ' /  | |    | |     | |  | |__  |  \| |\ \  /\  / /  \  | |__) | |__ ______| |__) | (___
|  <   | |    | |     | |  |  __| | . ` | \ \/  \/ / /\ \ |  _  /|  __|______|  _  / \___ \
| . \ _| |_   | |     | |  | |____| |\  |  \  /\  / ____ \| | \ \| |____     | | \ \ ____) |
|_|\_\_____|  |_|     |_|  |______|_| \_|   \/  \/_/    \_\_|  \_\______|    |_|  \_\_____/
"#;

const MENU_ITEMS: &[&str] = &[
    "Run SFC Scannow",
    "Run DISM RestoreHealth",
    "Show IP Configuration",
    "Show Windows Version",
    "Show Disk Usage",
    "Flush DNS Cache",
    "Renew IP Address",
    "Internet Connectivity Test",
    "Clean Temporary Files",
    "Empty Recycle Bin",
    "Exit",
];

const TEMP_LOCATIONS: &[&str] = &[
    r"C:\Windows\Temp",
    // %TEMP% is resolved at runtime; see clean_temp_files()
];

// Admin helpers

#[cfg(windows)]
fn is_admin() -> bool {
    use winapi::um::securitybaseapi::{AllocateAndInitializeSid, CheckTokenMembership, FreeSid};
    use winapi::um::winnt::{
        DOMAIN_ALIAS_RID_ADMINS, PSID, SECURITY_BUILTIN_DOMAIN_RID, SECURITY_NT_AUTHORITY,
        SID_IDENTIFIER_AUTHORITY,
    };

    unsafe {
        let mut authority = SID_IDENTIFIER_AUTHORITY {
            Value: SECURITY_NT_AUTHORITY,
        };
        let mut admin_group: PSID = std::ptr::null_mut();

        let ok = AllocateAndInitializeSid(
            &mut authority,
            2, // nSubAuthorityCount: we need exactly 2 sub-authorities below
            SECURITY_BUILTIN_DOMAIN_RID, // dwSubAuthority0: the built-in domain (S-1-5-32)
            DOMAIN_ALIAS_RID_ADMINS, // dwSubAuthority1: the Administrators alias (RID 544)
            0, // dwSubAuthority2 – unused
            0, // dwSubAuthority3 – unused
            0, // dwSubAuthority4 – unused
            0, // dwSubAuthority5 – unused
            0, // dwSubAuthority6 – unused
            0, // dwSubAuthority7 – unused
            &mut admin_group,
        );
        if ok == 0 {
            return false;
        }

        let mut is_member: i32 = 0;
        let result = CheckTokenMembership(std::ptr::null_mut(), admin_group, &mut is_member);
        FreeSid(admin_group);

        result != 0 && is_member != 0
    }
}

#[cfg(not(windows))]
fn is_admin() -> bool {
    true
}

#[cfg(windows)]
fn run_as_admin() {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::shellapi::ShellExecuteW;
    use winapi::um::winuser::SW_SHOW;

    println!("{YELLOW}Requesting administrator privileges…{RESET}");

    let exe = std::env::current_exe().unwrap();
    let exe_w: Vec<u16> = OsStr::new(exe.to_str().unwrap())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOW as i32,
        )
    };

    if result as usize <= 32 {
        println!("{RED}Administrator privileges were denied.{RESET}");
        pause();
    }
    std::process::exit(0);
}

#[cfg(not(windows))]
fn run_as_admin() {
    println!("{YELLOW}Not on Windows – skipping privilege elevation.{RESET}");
}

// UI helpers

fn clear_screen() {
    if cfg!(windows) {
        let _ = Command::new("cmd").args(["/C", "cls"]).status();
    } else {
        print!("\x1b[2J\x1b[H");
        let _ = io::stdout().flush();
    }
}

fn pause() {
    print!("\nPress Enter to continue…");
    let _ = io::stdout().flush();
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
}

fn print_menu() {
    clear_screen();
    println!("{RED}{LOGO}{RESET}");
    for (i, item) in MENU_ITEMS.iter().enumerate() {
        println!("{RED}{}. {item}{RESET}", i + 1);
    }
}

fn prompt(msg: &str) -> String {
    print!("{msg}");
    let _ = io::stdout().flush();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap_or_default();
    buf.trim().to_string()
}

// Command runners

fn run_command(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_powershell(script: &str) -> bool {
    run_command("powershell", &["-Command", script])
}

// Features

fn run_sfc() {
    println!("{RED}Running SFC Scan…{RESET}");
    if !run_command("sfc", &["/scannow"]) {
        println!("{RED}SFC scan failed.{RESET}");
    }
    pause();
}

fn run_dism() {
    println!("{RED}Running DISM RestoreHealth…{RESET}");
    if !run_command("dism", &["/Online", "/Cleanup-Image", "/RestoreHealth"]) {
        println!("{RED}DISM failed.{RESET}");
    }
    pause();
}

fn show_ip() {
    println!("{RED}IP Configuration:{RESET}");
    if !run_command("ipconfig", &[]) {
        println!("{RED}Failed to retrieve IP information.{RESET}");
    }
    pause();
}

fn show_windows_version() {
    println!("{RED}Windows Version:{RESET}");
    if !Command::new("cmd")
        .args(["/C", "ver"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        println!("{RED}Failed to retrieve Windows version.{RESET}");
    }
    pause();
}

fn show_disk_usage() {
    println!("{RED}Disk Usage Information:{RESET}");
    let script = concat!(
        "Get-PSDrive -PSProvider FileSystem | ",
        "Select Name,",
        "@{Name='Free(GB)';Expression={[math]::Round($_.Free/1GB,2)}},",
        "@{Name='Used(GB)';Expression={[math]::Round($_.Used/1GB,2)}}",
    );
    if !run_powershell(script) {
        println!("{RED}Failed to retrieve disk information.{RESET}");
    }
    pause();
}

fn flush_dns() {
    println!("{RED}Flushing DNS Cache…{RESET}");
    if run_command("ipconfig", &["/flushdns"]) {
        println!("{GREEN}DNS cache flushed successfully.{RESET}");
    } else {
        println!("{RED}Failed to flush DNS cache.{RESET}");
    }
    pause();
}

fn renew_ip() {
    println!("{RED}Renewing IP Address…{RESET}");
    let ok = run_command("ipconfig", &["/release"]) && run_command("ipconfig", &["/renew"]);
    if ok {
        println!("{GREEN}IP renewed successfully.{RESET}");
    } else {
        println!("{RED}Failed to renew IP address.{RESET}");
    }
    pause();
}

fn test_internet() {
    println!("{RED}Testing Internet Connectivity…{RESET}");
    match Command::new("ping").args(["8.8.8.8", "-n", "4"]).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let online = stdout.contains("TTL=");
            let (color, status) = if online {
                (GREEN, "ONLINE")
            } else {
                (RED, "OFFLINE")
            };
            println!("{color}\nInternet Status: {status}\n{RESET}");
            print!("{stdout}");
        }
        Err(_) => println!("{RED}Connectivity test failed.{RESET}"),
    }
    pause();
}

fn clean_temp_files() {
    println!("{RED}Cleaning Temporary Files…{RESET}");
    let mut deleted: usize = 0;

    let mut locations: Vec<String> = TEMP_LOCATIONS.iter().map(|s| s.to_string()).collect();
    if let Ok(temp) = std::env::var("TEMP") {
        locations.push(temp);
    }
    locations.sort();
    locations.dedup();

    for location in &locations {
        let dir = Path::new(location);
        if !dir.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let ok = if path.is_file() || path.is_symlink() {
                    fs::remove_file(&path).is_ok()
                } else {
                    fs::remove_dir_all(&path).is_ok()
                };
                if ok {
                    deleted += 1;
                }
            }
        }
    }

    println!("{GREEN}Deleted approximately {deleted} temporary items.{RESET}");
    pause();
}

#[cfg(windows)]
fn empty_recycle_bin() {
    use winapi::shared::winerror::HRESULT;
    use winapi::um::shellapi::SHEmptyRecycleBinW;

    // Flags: skip confirmation dialog, skip progress UI, skip the empty sound.
    const SHERB_NOCONFIRMATION: u32 = 0x0000_0001;
    const SHERB_NOPROGRESSUI: u32 = 0x0000_0002;
    const SHERB_NOSOUND: u32 = 0x0000_0004;
    // Returned by SHEmptyRecycleBinW when the bin is already empty on every drive.
    const E_UNEXPECTED: HRESULT = 0x8000_FFFFu32 as HRESULT;

    println!("{RED}Emptying Recycle Bin…{RESET}");

    let flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
    let hr: HRESULT =
        unsafe { SHEmptyRecycleBinW(std::ptr::null_mut(), std::ptr::null(), flags) };

    if hr == 0 {
        println!("{GREEN}Recycle Bin emptied successfully.{RESET}");
    } else if hr == E_UNEXPECTED {
        println!("{GREEN}Recycle Bin is already empty.{RESET}");
    } else {
        println!("{RED}Failed to empty Recycle Bin (HRESULT: 0x{:08X}).{RESET}", hr as u32);
    }

    pause();
}

#[cfg(not(windows))]
fn empty_recycle_bin() {
    println!("{YELLOW}Not on Windows – nothing to empty.{RESET}");
    pause();
}

// Main

fn main() {
    #[cfg(windows)]
    {
        use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
        use winapi::um::handleapi::INVALID_HANDLE_VALUE;
        use winapi::um::processenv::GetStdHandle;
        use winapi::um::winbase::STD_OUTPUT_HANDLE;
        use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        unsafe {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            if h != INVALID_HANDLE_VALUE {
                let mut mode: u32 = 0;
                GetConsoleMode(h, &mut mode);
                SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }

    if !is_admin() {
        run_as_admin();
        return;
    }

    loop {
        print_menu();
        let choice = prompt("\nEnter your choice: ");

        match choice.as_str() {
            "1" => run_sfc(),
            "2" => run_dism(),
            "3" => show_ip(),
            "4" => show_windows_version(),
            "5" => show_disk_usage(),
            "6" => flush_dns(),
            "7" => renew_ip(),
            "8" => test_internet(),
            "9" => clean_temp_files(),
            "10" => empty_recycle_bin(),
            "11" => {
                println!("{GREEN}Exiting…{RESET}");
                break;
            }
            _ => {
                println!("{RED}Invalid choice.{RESET}");
                pause();
            }
        }
    }
}