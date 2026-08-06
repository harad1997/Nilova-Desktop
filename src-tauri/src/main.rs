#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::io::Write;
use std::process::{Child, Command};
use std::sync::Mutex;
use serde_json::json;
use tauri::State;

struct AppState {
    child: Mutex<Option<Child>>,
}

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
    let mut security = String::new();
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        match k {
            "path" => path = v.replace("%2F", "/").replace("%40", "@"),
            "host" => host = v.replace("%40", "@"),
            "type" => ty = v.to_string(),
            "security" => security = v.to_string(),
            _ => {}
        }
    }

    Some((id, address, port, ty, path, host))
}

fn build_config(link: &str) -> Option<String> {
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

    let outbound = json!({
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
    });

    let config = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": { "udp": true }
            }
        ],
        "outbounds": [outbound]
    });

    Some(config.to_string())
}

fn run_xray(link: String, state: State<'_, AppState>) -> Result<String, String> {
    let config_json = build_config(&link).ok_or("لینک VLESS معتبر نیست")?;

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

    let mut state = state.child.lock().map_err(|e| e.to_string())?;
    if state.is_some() {
        return Err("از قبل متصل است".into());
    }

    let child = Command::new(&xray_path)
        .arg("-c")
        .arg(&config_path)
        .spawn()
        .map_err(|e| format!("خطا در اجرای هسته: {}", e))?;

    *state = Some(child);
    Ok("اتصال برقرار شد".into())
}

fn stop_xray(state: State<'_, AppState>) -> Result<String, String> {
    let mut state = state.child.lock().map_err(|e| e.to_string())?;
    if let Some(mut child) = state.take() {
        let _ = child.kill();
        let _ = child.wait();
        Ok("اتصال قطع شد".into())
    } else {
        Ok("برنامه متصل نیست".into())
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            child: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![run_xray, stop_xray])
        .run(tauri::generate_context!())
        .expect("خطا هنگام اجرای برنامه");
}
