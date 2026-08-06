#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::io::Write;
use std::process::{Child, Command};
use std::sync::Mutex;

use serde_json::json;
use tauri::State;

use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use winreg::HKCU;

struct AppState {
    child: Mutex<Option<Child>>,
}

const PROXY_SERVER: &str = "http=127.0.0.1:10809;socks=127.0.0.1:10808";
const PROXY_OVERRIDE: &str = "<local>";
const INTERNET_SETTINGS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

fn parse_vless(link: &str) -> Option<(String, String, String, String, String, String)> {
    let rest = link.strip_prefix("vless://")?;
    let main = rest.split('#').next()?;
    let at = main.find('@')?;
    let id = main[..at].to_string();
    let after = &main[at + 1..];
    let q = after.find('?');
    let (host_port, query) = match q {
        Some(i) => (&after[..i], &after[i + 1..]),
        None => (after, ""),
    };
    let colon = host_port.rfind(':')?;
    let address = host_port[..colon].to_string();
    let port = host_port[colon + 1..].to_string();
    let mut path = String::new();
    let mut host = String::new();
    let mut ty = String::from("tcp");
    let mut _security = String::new();
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        match k {
            "path" => path = v.replace("%2F", "/").replace("%40", "@"),
            "host" => host = v.replace("%40", "@"),
            "type" => ty = v.to_string(),
            "security" => _security = v.to_string(),
            _ => {}
        }
    }
    Some((id, address, port, ty, path, host))
}

/// خروجی VLESS را از لینک می‌سازد (مشترک بین حالت پروکسی و TUN).
fn build_outbound(link: &str) -> Option<serde_json::Value> {
    let (id, address, port, ty, path, host) = parse_vless(link)?;
    let mut stream_settings = serde_json::Map::new();
    stream_settings.insert("network".into(), json!(ty));
    if ty == "ws" {
        let mut ws = serde_json::Map::new();
        if !path.is_empty() {
            ws.insert("path".into(), json!(path));
        }
        if !host.is_empty() {
            ws.insert("headers".into(), json!({ "Host": host }));
        }
        stream_settings.insert("wsSettings".into(), json!(ws));
    }
    Some(json!({
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": id,
                            "encryption": "none"
                        }
                    ]
                }
            ]
        },
        "streamSettings": stream_settings
    }))
}

/// پیکربندی حالت پروکسی: ورودی‌های SOCKS و HTTP روی پورت‌های محلی.
fn build_config(link: &str) -> Option<String> {
    let outbound = build_outbound(link)?;
    let config = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": { "udp": true }
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {}
            }
        ],
        "outbounds": [outbound]
    });
    Some(config.to_string())
}

/// پیکربندی حالت TUN: یک آداپتور مجازی که کل ترافیک ویندوز را می‌گیرد.
fn build_tun_config(link: &str) -> Option<String> {
    let outbound = build_outbound(link)?;
    let config = json!({
        "log": { "loglevel": "warning" },
        "dns": {
            "servers": ["1.1.1.1", "8.8.8.8"]
        },
        "inbounds": [
            {
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "address": ["10.0.0.1", "fd00::1"],
                    "mtu": 1500,
                    "autoRoute": true,
                    "strictRoute": false,
                    "stack": "system"
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls", "quic"]
                }
            }
        ],
        "outbounds": [outbound]
    });
    Some(config.to_string())
}

/// به ویندوز اطلاع می‌دهد که تنظیمات پروکسی عوض شده تا برنامه‌های باز فوراً آن را ببینند.
fn notify_wininet() {
    unsafe {
        let _ = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let _ = InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

/// پروکسی سیستم ویندوز را روشن یا خاموش می‌کند (فقط حساب کاربر جاری — بدون نیاز به مدیر).
fn set_proxy(on: bool) -> Result<(), String> {
    let (key, _) = HKCU
        .create_subkey(INTERNET_SETTINGS)
        .map_err(|e| format!("خطا در بازکردن تنظیمات پروکسی: {}", e))?;

    if on {
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| format!("خطا در فعال‌کردن پروکسی: {}", e))?;
        key.set_value("ProxyServer", &PROXY_SERVER)
            .map_err(|e| format!("خطا در تنظیم نشانی پروکسی: {}", e))?;
        key.set_value("ProxyOverride", &PROXY_OVERRIDE)
            .map_err(|e| format!("خطا در تنظیم استثناهای پروکسی: {}", e))?;
    } else {
        // فقط اگر پروکسی خودِ نیلووا هنوز برقرار است، آن را خاموش کن تا
        // پروکسی دستی کاربر (مثلاً اداری) از بین نرود.
        let ours = key
            .get_value::<String, _>("ProxyServer")
            .map(|v| v.contains("127.0.0.1:10808"))
            .unwrap_or(true);
        if ours {
            key.set_value("ProxyEnable", &0u32)
                .map_err(|e| format!("خطا در خاموش‌کردن پروکسی: {}", e))?;
        }
    }

    notify_wininet();
    Ok(())
}

/// آیا برنامه با دسترسی مدیر اجرا شده است؟ (چک سطح یکپارچگی بالا)
fn is_admin() -> bool {
    match Command::new("whoami").arg("/groups").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains("S-1-16-12288"),
        Err(_) => false,
    }
}

/// هسته Xray را با پیکربندی داده‌شده اجرا می‌کند (مشترک بین حالت پروکسی و TUN).
fn start_core(config_json: &str, state: State<'_, AppState>, with_proxy: bool) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|_| "خطا در پیدا کردن مسیر برنامه")?
        .parent()
        .ok_or("خطا در مسیر برنامه")?
        .to_path_buf();

    let xray_path = exe_path.join("xray.exe");
    if !xray_path.exists() {
        return Err("فایل xray.exe پیدا نشد".into());
    }

    let config_path = exe_path.join("config.json");
    let mut file = fs::File::create(&config_path).map_err(|e| e.to_string())?;
    file.write_all(config_json.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut guard = state.child.lock().map_err(|e| e.to_string())?;
    if guard.is_some() {
        return Err("از قبل متصل است".into());
    }

    let child = Command::new(&xray_path)
        .arg("-c")
        .arg(&config_path)
        .spawn()
        .map_err(|e| format!("خطا در اجرای هسته: {}", e))?;

    if with_proxy {
        // اگر تنظیم پروکسی سیستم ناموفق بود، هسته را هم متوقف کن تا حالت ناسازگار پیش نیاید.
        if let Err(e) = set_proxy(true) {
            let mut c = child;
            let _ = c.kill();
            let _ = c.wait();
            return Err(e);
        }
    }

    *guard = Some(child);
    Ok(())
}

#[tauri::command]
fn run_xray(link: String, state: State<'_, AppState>) -> Result<String, String> {
    let config_json = build_config(&link).ok_or("لینک VLESS معتبر نیست")?;
    start_core(&config_json, state, true)?;
    Ok("اتصال برقرار شد؛ پروکسی سیستم ویندوز روشن شد".into())
}

#[tauri::command]
fn run_tun(link: String, state: State<'_, AppState>) -> Result<String, String> {
    if !is_admin() {
        return Err("حالت TUN نیازمند اجرای برنامه به عنوان مدیر است. برنامه را ببندید، روی آن کلیک راست کنید و «اجرا به عنوان مدیر» را بزنید.".into());
    }
    let config_json = build_tun_config(&link).ok_or("لینک VLESS معتبر نیست")?;
    start_core(&config_json, state, false)?;
    Ok("اتصال TUN برقرار شد؛ کل ترافیک ویندوز از طریق پروکسی عبور می‌کند".into())
}

#[tauri::command]
fn stop_xray(state: State<'_, AppState>) -> Result<String, String> {
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;

    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    let _ = set_proxy(false);
    Ok("اتصال قطع شد؛ پروکسی سیستم ویندوز خاموش شد".into())
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            child: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![run_xray, run_tun, stop_xray])
        .run(tauri::generate_context!())
        .expect("خطا هنگام اجرای برنامه");
}
