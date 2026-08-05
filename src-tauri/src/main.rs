#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;

#[derive(Serialize)]
struct VlessInfo {
    id: String,
    address: String,
    port: String,
}

fn parse_vless(link: &str) -> Option<VlessInfo> {
    let rest = link.strip_prefix("vless://")?;
    let main = rest.split('#').next()?;
    let at = main.find('@')?;
    let id = main[..at].to_string();
    let after = &main[at + 1..];
    let query_start = after.find('?').unwrap_or(after.len());
    let host_port = &after[..query_start];
    let colon = host_port.rfind(':')?;
    let address = host_port[..colon].to_string();
    let port = host_port[colon + 1..].to_string();
    Some(VlessInfo { id, address, port })
}

#[tauri::command]
fn test_parse(link: String) -> Result<String, String> {
    match parse_vless(&link) {
        Some(info) => Ok(format!(
            "آدرس: {} پورت: {} شناسه: {}",
            info.address, info.port, info.id
        )),
        None => Err("لینک VLESS معتبر نیست".into()),
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![test_parse])
        .run(tauri::generate_context!())
        .expect("خطا هنگام اجرای برنامه");
}
