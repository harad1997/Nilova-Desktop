#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::json;
use tauri::{Emitter, Manager, State};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use winreg::HKCU;

/// اجرای فرایندهای فرزند بدون باز شدن پنجرهٔ کنسول.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn silent(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/* ================= وضعیت برنامه ================= */

struct TrafficAcc {
    loaded: bool,
    last_up: u64,
    last_down: u64,
    last_t: Option<Instant>,
    next_rollover: Instant,
    up_speed: f64,
    down_speed: f64,
    today_up: u64,
    today_down: u64,
    month_up: u64,
    month_down: u64,
    total_up: u64,
    total_down: u64,
    date: String,
    month: String,
}

impl Default for TrafficAcc {
    fn default() -> Self {
        TrafficAcc {
            loaded: false,
            last_up: 0,
            last_down: 0,
            last_t: None,
            next_rollover: Instant::now(),
            up_speed: 0.0,
            down_speed: 0.0,
            today_up: 0,
            today_down: 0,
            month_up: 0,
            month_down: 0,
            total_up: 0,
            total_down: 0,
            date: String::new(),
            month: String::new(),
        }
    }
}

/// پورت‌های آزاد انتخاب‌شده برای هر اتصال — تا با برنامه‌های دیگر (مثل v2rayN) تداخل نکند.
#[derive(Clone, Copy)]
struct CorePorts {
    http: u16,
    socks: u16,
    metrics: u16,
}

struct AppState {
    child: Mutex<Option<Child>>,
    traffic: Mutex<TrafficAcc>,
    ports: Mutex<Option<CorePorts>>,
    log_pos: Mutex<u64>,

    // Routeهای موقت حالت TUN برای پاک‌سازی هنگام قطع اتصال
        tun_bypasses: Mutex<Vec<String>>,
    tun_default_route: Mutex<bool>,
    tun_ifindex: Mutex<Option<String>>,

    // ذخیرهٔ نشانی واقعی (بدون تونل) برای نمایش هنگام حالت TUN
    cached_direct_ip: Mutex<Option<serde_json::Value>>,
}

const PROXY_OVERRIDE: &str = "<local>";
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/* ================= ساخت پیکربندی ================= */

/// تمام پارامترهای یک لینک VLESS را استخراج می‌کند (tls / reality / ws / grpc).
struct VlessInfo {
    id: String,
    address: String,
    port: String,
    network: String,
    path: String,
    host: String,
    security: String,
    sni: String,
    fp: String,
    pbk: String,
    sid: String,
    spx: String,
    flow: String,
    alpn: String,
    service_name: String,
}

fn parse_vless(link: &str) -> Option<VlessInfo> {
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

    let mut info = VlessInfo {
        id,
        address,
        port,
        network: String::from("tcp"),
        path: String::new(),
        host: String::new(),
        security: String::new(),
        sni: String::new(),
        fp: String::new(),
        pbk: String::new(),
        sid: String::new(),
        spx: String::new(),
        flow: String::new(),
        alpn: String::new(),
        service_name: String::new(),
    };
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        match k {
            "path" => info.path = v.replace("%2F", "/").replace("%40", "@"),
            "host" => info.host = v.replace("%40", "@"),
            "type" => info.network = v.to_string(),
            "security" => info.security = v.to_string(),
            "sni" => info.sni = v.to_string(),
            "fp" => info.fp = v.to_string(),
            "pbk" => info.pbk = v.to_string(),
            "sid" => info.sid = v.to_string(),
            "spx" => info.spx = v.to_string(),
            "flow" => info.flow = v.to_string(),
            "alpn" => info.alpn = v.to_string(),
            "serviceName" => info.service_name = v.replace("%2F", "/"),
            _ => {}
        }
    }
    Some(info)
}

/// بر اساس نوع لینک، تابع مناسب را صدا می‌زند.
fn build_outbound(link: &str) -> Option<serde_json::Value> {
    if link.starts_with("vmess://") {
        build_vmess_outbound(link)
    } else if link.starts_with("trojan://") {
        build_trojan_outbound(link)
    } else if link.starts_with("ss://") {
        build_ss_outbound(link)
    } else if link.starts_with("socks5://") {
        build_socks_outbound(link)
    } else if link.starts_with("http://") {
        build_http_outbound(link)
    } else if link.starts_with("wireguard://") || link.starts_with("wg://") {
        build_wireguard_outbound(link)
    } else {
        build_vless_outbound(link)
    }
}

/// دیکد سادهٔ base64 (استاندارد و URL-safe) بدون padding سخت‌گیرانه.
fn b64decode(s: &str) -> Option<Vec<u8>> {
    let mut clean: String = s
        .chars()
        .filter(|c| *c != '\n' && *c != '\r' && *c != ' ')
        .collect();

    // URL-safe به استاندارد تبدیل کن
    clean = clean.replace('-', "+").replace('_', "/");

    // حذف padding موجود؛ ادامهٔ تابع خودش بخش پایانی Base64 را پردازش می‌کند.
    clean = clean.trim_end_matches('=').to_string();

    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = Vec::new();
    let bytes = clean.as_bytes();

    let mut i = 0;
    while i + 4 <= bytes.len() {
        let mut n = 0u32;
        for &c in &bytes[i..i + 4] {
            let v = T.iter().position(|&t| t == c)? as u32;
            n = (n << 6) | v;
        }
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }

    // پدینگ آخر
    let rem = bytes.len() - i;
    if rem == 2 {
        let a = T.iter().position(|&t| t == bytes[i])? as u32;
        let b = T.iter().position(|&t| t == bytes[i + 1])? as u32;
        out.push(((a << 2) | (b >> 4)) as u8);
    } else if rem == 3 {
        let a = T.iter().position(|&t| t == bytes[i])? as u32;
        let b = T.iter().position(|&t| t == bytes[i + 1])? as u32;
        let c = T.iter().position(|&t| t == bytes[i + 2])? as u32;
        out.push(((a << 2) | (b >> 4)) as u8);
        out.push(((b << 4) | (c >> 2)) as u8);
    }

    Some(out)
}
/// خروجی VMess را از لینک vmess:// (JSON بیس۶۴) می‌سازد.
fn build_vmess_outbound(link: &str) -> Option<serde_json::Value> {
    let raw = link.strip_prefix("vmess://")?;
    let json_str = String::from_utf8(b64decode(raw)?).ok()?;
    let v: serde_json::Value = serde_json::from_str(&json_str).ok()?;

    let address = v["add"].as_str()?.to_string();
    let port: u16 = v["port"].as_str()?.parse().ok()?;
    let id = v["id"].as_str()?.to_string();
    let aid = v["aid"].as_str().unwrap_or("0").to_string();
    let scy = v["scy"].as_str().unwrap_or("auto").to_string();
    let net = v["net"].as_str().unwrap_or("tcp").to_string();
    let host = v["host"].as_str().unwrap_or("").to_string();
    let path = v["path"].as_str().unwrap_or("").to_string();
    let tls = v["tls"].as_str().unwrap_or("").to_string();
    let sni = v["sni"].as_str().unwrap_or("").to_string();
    let fp = v["fp"].as_str().unwrap_or("").to_string();
    let service_name = v["serviceName"].as_str().unwrap_or("").to_string();

    let mut stream = serde_json::Map::new();
    stream.insert("network".into(), json!(net));

    if tls == "tls" {
        let mut t = serde_json::Map::new();
        let server_name = if !sni.is_empty() {
            sni.clone()
        } else if !host.is_empty() {
            host.clone()
        } else {
            address.clone()
        };
        t.insert("serverName".into(), json!(server_name));
        if !fp.is_empty() {
            t.insert("fingerprint".into(), json!(fp));
        }
        stream.insert("tlsSettings".into(), json!(t));
    }

    if net == "ws" {
        let mut ws = serde_json::Map::new();
        if !path.is_empty() {
            ws.insert("path".into(), json!(path));
        }
        if !host.is_empty() {
            ws.insert("host".into(), json!(host));
        }
        stream.insert("wsSettings".into(), json!(ws));
    }

    if net == "grpc" && !service_name.is_empty() {
        let mut gr = serde_json::Map::new();
        gr.insert("serviceName".into(), json!(service_name));
        stream.insert("grpcSettings".into(), json!(gr));
    }

    let mut user = serde_json::Map::new();
    user.insert("id".into(), json!(id));
    user.insert("alterId".into(), json!(aid));
    user.insert("security".into(), json!(scy));

    Some(json!({
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [ user ]
                }
            ]
        },
        "streamSettings": stream
    }))
}

fn build_vless_outbound(link: &str) -> Option<serde_json::Value> {
    let i = parse_vless(link)?;
    let port: u16 = i.port.parse().ok()?;

    let mut stream = serde_json::Map::new();
    stream.insert("network".into(), json!(i.network));
    let security = if i.security.is_empty() {
        "none"
    } else {
        i.security.as_str()
    };
    stream.insert("security".into(), json!(security));

    if i.security == "tls" {
        let mut tls = serde_json::Map::new();
        let server_name = if !i.sni.is_empty() {
            i.sni.clone()
        } else if !i.host.is_empty() {
            i.host.clone()
        } else {
            i.address.clone()
        };
        tls.insert("serverName".into(), json!(server_name));
        if !i.fp.is_empty() {
            tls.insert("fingerprint".into(), json!(i.fp));
        }
        if !i.alpn.is_empty() {
            let alpn: Vec<&str> = i
                .alpn
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            tls.insert("alpn".into(), json!(alpn));
        }
        stream.insert("tlsSettings".into(), json!(tls));
    }
    if i.security == "reality" {
        let mut rt = serde_json::Map::new();
        let server_name = if !i.sni.is_empty() {
            i.sni.clone()
        } else {
            i.host.clone()
        };
        if !server_name.is_empty() {
            rt.insert("serverName".into(), json!(server_name));
        }
        if !i.fp.is_empty() {
            rt.insert("fingerprint".into(), json!(i.fp));
        }
        if !i.pbk.is_empty() {
            rt.insert("publicKey".into(), json!(i.pbk));
        }
        if !i.sid.is_empty() {
            rt.insert("shortId".into(), json!(i.sid));
        }
        if !i.spx.is_empty() {
            rt.insert("spiderX".into(), json!(i.spx));
        }
        stream.insert("realitySettings".into(), json!(rt));
    }
    if i.network == "ws" {
        let mut ws = serde_json::Map::new();
        if !i.path.is_empty() {
            ws.insert("path".into(), json!(i.path));
        }
        if !i.host.is_empty() {
            ws.insert("host".into(), json!(i.host));
        }

        stream.insert("wsSettings".into(), json!(ws));
    }
    if i.network == "grpc" {
        let mut gr = serde_json::Map::new();
        if !i.service_name.is_empty() {
            gr.insert("serviceName".into(), json!(i.service_name));
        }
        stream.insert("grpcSettings".into(), json!(gr));
    }

    let mut user = serde_json::Map::new();
    user.insert("id".into(), json!(i.id));
    user.insert("encryption".into(), json!("none"));
    if !i.flow.is_empty() {
        user.insert("flow".into(), json!(i.flow));
    }

    Some(json!({
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": i.address,
                    "port": port,
                    "users": [ user ]
                }
            ]
        },
        "streamSettings": stream
    }))
}
/// اطلاعات یک لینک Trojan را استخراج میکند (tls / ws / grpc).
struct TrojanInfo {
    password: String,
    address: String,
    port: String,
    network: String,
    path: String,
    host: String,
    security: String,
    sni: String,
    fp: String,
    alpn: String,
    service_name: String,
}

fn parse_trojan(link: &str) -> Option<TrojanInfo> {
    let rest = link.strip_prefix("trojan://")?;
    let main = rest.split('#').next()?;
    let at = main.find('@')?;
    let password = main[..at].to_string();
    let after = &main[at + 1..];
    let q = after.find('?');
    let (host_port, query) = match q {
        Some(i) => (&after[..i], &after[i + 1..]),
        None => (after, ""),
    };
    let colon = host_port.rfind(':')?;
    let address = host_port[..colon].to_string();
    let port = host_port[colon + 1..].to_string();

    let mut info = TrojanInfo {
        password,
        address,
        port,
        network: String::from("tcp"),
        path: String::new(),
        host: String::new(),
        security: String::from("tls"), // پیشفرض تروجان TLS است
        sni: String::new(),
        fp: String::new(),
        alpn: String::new(),
        service_name: String::new(),
    };
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        match k {
            "type" => info.network = v.to_string(),
            "path" => info.path = v.replace("%2F", "/").replace("%40", "@"),
            "host" => info.host = v.replace("%40", "@"),
            "security" => info.security = v.to_string(),
            "sni" => info.sni = v.to_string(),
            "fp" => info.fp = v.to_string(),
            "alpn" => info.alpn = v.to_string(),
            "serviceName" => info.service_name = v.replace("%2F", "/"),
            _ => {}
        }
    }
    Some(info)
}

/// خروجی Trojan را میسازد — ساختار streamSettings دقیقاً مثل VLESS است.
fn build_trojan_outbound(link: &str) -> Option<serde_json::Value> {
    let i = parse_trojan(link)?;
    let port: u16 = i.port.parse().ok()?;

    let mut stream = serde_json::Map::new();
    stream.insert("network".into(), json!(i.network));
    let security = if i.security.is_empty() {
        "tls"
    } else {
        i.security.as_str()
    };
    stream.insert("security".into(), json!(security));

    if i.security == "tls" {
        let mut tls = serde_json::Map::new();
        let server_name = if !i.sni.is_empty() {
            i.sni.clone()
        } else if !i.host.is_empty() {
            i.host.clone()
        } else {
            i.address.clone()
        };
        tls.insert("serverName".into(), json!(server_name));
        if !i.fp.is_empty() {
            tls.insert("fingerprint".into(), json!(i.fp));
        }
        if !i.alpn.is_empty() {
            let alpn: Vec<&str> = i
                .alpn
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            tls.insert("alpn".into(), json!(alpn));
        }
        stream.insert("tlsSettings".into(), json!(tls));
    }
    if i.network == "ws" {
        let mut ws = serde_json::Map::new();
        if !i.path.is_empty() {
            ws.insert("path".into(), json!(i.path));
        }
        if !i.host.is_empty() {
            ws.insert("host".into(), json!(i.host));
        }
        stream.insert("wsSettings".into(), json!(ws));
    }
    if i.network == "grpc" {
        let mut gr = serde_json::Map::new();
        if !i.service_name.is_empty() {
            gr.insert("serviceName".into(), json!(i.service_name));
        }
        stream.insert("grpcSettings".into(), json!(gr));
    }

    Some(json!({
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": i.address,
                    "port": port,
                    "password": i.password,
                    "level": 0
                }
            ]
        },
        "streamSettings": stream
    }))
}
/// اطلاعات یک لینک Shadowsocks را استخراج میکند (هر سه قالب رایج).
struct SsInfo {
    method: String,
    password: String,
    address: String,
    port: String,
    plugin: String,
}

/// دیکد سادهٔ درصدی (مثل %40 و %2F) — برای پارامترهای SIP002.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = (bytes[i + 1] as char).to_digit(16);
            let l = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (h, l) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn b64decode_str(s: &str) -> Option<String> {
    String::from_utf8(b64decode(s)?).ok()
}

fn parse_ss(link: &str) -> Option<SsInfo> {
    let rest = link.strip_prefix("ss://")?;
    let main = rest.split('#').next()?;
    let (body, query) = match main.find('?') {
        Some(q) => (&main[..q], &main[q + 1..]),
        None => (main, ""),
    };
    let plugin = query
        .split('&')
        .find_map(|p| p.strip_prefix("plugin="))
        .map(url_decode)
        .unwrap_or_default();

    // دو حالت:  userinfo@host:port  یا  کلِ base64(method:password@host:port)
    let (method, password, host_port) = if let Some(at) = body.find('@') {
        let userinfo = &body[..at];
        let host_port = body[at + 1..].to_string();
        if let Some(dec) = b64decode_str(userinfo) {
            let c = dec.find(':')?;
            (dec[..c].to_string(), dec[c + 1..].to_string(), host_port)
        } else {
            // قالب SIP002: method:password با درصدی‌بودن
            let dec = url_decode(userinfo);
            let c = dec.find(':')?;
            (dec[..c].to_string(), dec[c + 1..].to_string(), host_port)
        }
    } else {
        let dec = b64decode_str(body)?;
        let at = dec.rfind('@')?;
        let host_port = dec[at + 1..].to_string();
        let userinfo = &dec[..at];
        let c = userinfo.find(':')?;
        (
            userinfo[..c].to_string(),
            userinfo[c + 1..].to_string(),
            host_port,
        )
    };

    let colon = host_port.rfind(':')?;
    let address = host_port[..colon].to_string();
    let port = host_port[colon + 1..].to_string();

    Some(SsInfo {
        method,
        password,
        address,
        port,
        plugin,
    })
}

/// خروجی Shadowsocks را میسازد — بدون streamSettings چون SS روی TCP ساده است.
fn build_ss_outbound(link: &str) -> Option<serde_json::Value> {
    let i = parse_ss(link)?;
    let port: u16 = i.port.parse().ok()?;

    let mut server = serde_json::Map::new();
    server.insert("address".into(), json!(i.address));
    server.insert("port".into(), json!(port));
    server.insert("method".into(), json!(i.method));
    server.insert("password".into(), json!(i.password));
    if !i.plugin.is_empty() {
        server.insert("plugin".into(), json!(i.plugin));
    }

    Some(json!({
        "protocol": "shadowsocks",
        "settings": {
            "servers": [ server ]
        }
    }))
}
/// اطلاعات یک لینک SOCKS5 یا HTTP را استخراج میکند (user/pass اختیاری).
struct SimpleProxyInfo {
    user: String,
    pass: String,
    address: String,
    port: String,
}

fn parse_simple_proxy(link: &str, prefix: &str) -> Option<SimpleProxyInfo> {
    let rest = link.strip_prefix(prefix)?;
    let main = rest.split('#').next()?;
    let body = main.split('?').next().unwrap_or(main);
    let (userinfo, host_port) = match body.find('@') {
        Some(at) => (&body[..at], &body[at + 1..]),
        None => ("", body),
    };
    let colon = host_port.rfind(':')?;
    let address = host_port[..colon].to_string();
    let port = host_port[colon + 1..].to_string();

    let (user, pass) = if userinfo.is_empty() {
        (String::new(), String::new())
    } else {
        match userinfo.find(':') {
            Some(c) => (userinfo[..c].to_string(), userinfo[c + 1..].to_string()),
            None => (userinfo.to_string(), String::new()),
        }
    };

    Some(SimpleProxyInfo {
        user,
        pass,
        address,
        port,
    })
}

/// خروجی SOCKS5 را میسازد.
fn build_socks_outbound(link: &str) -> Option<serde_json::Value> {
    let i = parse_simple_proxy(link, "socks5://")?;
    let port: u16 = i.port.parse().ok()?;

    let mut server = serde_json::Map::new();
    server.insert("address".into(), json!(i.address));
    server.insert("port".into(), json!(port));
    if !i.user.is_empty() || !i.pass.is_empty() {
        let mut user = serde_json::Map::new();
        user.insert("user".into(), json!(i.user));
        user.insert("pass".into(), json!(i.pass));
        server.insert("users".into(), json!([user]));
    }

    Some(json!({
        "protocol": "socks",
        "settings": {
            "servers": [ server ]
        }
    }))
}

/// خروجی HTTP را میسازد.
fn build_http_outbound(link: &str) -> Option<serde_json::Value> {
    let i = parse_simple_proxy(link, "http://")?;
    let port: u16 = i.port.parse().ok()?;

    let mut server = serde_json::Map::new();
    server.insert("address".into(), json!(i.address));
    server.insert("port".into(), json!(port));
    if !i.user.is_empty() || !i.pass.is_empty() {
        let mut user = serde_json::Map::new();
        user.insert("user".into(), json!(i.user));
        user.insert("pass".into(), json!(i.pass));
        server.insert("users".into(), json!([user]));
    }

    Some(json!({
        "protocol": "http",
        "settings": {
            "servers": [ server ]
        }
    }))
}
/// اطلاعات یک لینک WireGuard را استخراج میکند (فرمت پارامتری و JSON بیس۶۴).
struct WireGuardInfo {
    secret_key: String,
    address: String,
    public_key: String,
    endpoint: String,
    pre_shared_key: String,
    reserved: Vec<u8>,
    mtu: u32,
}

/// یک پارامتر مشخص را از query برمیگرداند.
fn get_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{}=", key);
    query.split('&').find_map(|p| p.strip_prefix(&prefix))
}

/// اولین پارامتری که با یکی از کلیدهای دادهشده باشد را برمیگرداند.
fn get_param_any<'a>(query: &'a str, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| get_param(query, k))
}

fn parse_wireguard(link: &str) -> Option<WireGuardInfo> {
    let rest = link
        .strip_prefix("wireguard://")
        .or_else(|| link.strip_prefix("wg://"))?;
    let main = rest.split('#').next()?;
    let (query, body) = match main.find('?') {
        Some(q) => (&main[q + 1..], &main[..q]),
        None => ("", main),
    };

    if body.contains('@') || !query.is_empty() {
        // فرمت پارامتری: publickey@host:port?privateKey=...&ip=...&psk=...
        let (public_key, endpoint) = if let Some(at) = body.find('@') {
            (
                url_decode(&body[..at]),
                body[at + 1..].trim_end_matches('/').to_string(),
            )
        } else {
            let pk = get_param_any(
                query,
                &["publicKey", "public_key", "peer_pk", "peer_public_key"],
            )?;
            (url_decode(pk), body.trim_end_matches('/').to_string())
        };
        let secret_key = get_param_any(query, &["privateKey", "private_key", "pk"])
            .map(url_decode)
            .unwrap_or_default();
        let address = get_param_any(query, &["ip", "address", "local_address"])
            .map(url_decode)
            .unwrap_or_default();
        let pre_shared_key = get_param_any(query, &["psk", "preSharedKey", "pre_shared_key"])
            .map(url_decode)
            .unwrap_or_default();
        let reserved = get_param_any(query, &["reserved"])
            .map(|r| {
                r.split(',')
                    .filter_map(|x| x.trim().parse::<u8>().ok())
                    .collect::<Vec<u8>>()
            })
            .unwrap_or_default();
        let mtu = get_param_any(query, &["mtu"])
            .and_then(|m| m.parse().ok())
            .unwrap_or(1420);
        Some(WireGuardInfo {
            secret_key,
            address,
            public_key,
            endpoint,
            pre_shared_key,
            reserved,
            mtu,
        })
    } else {
        // فرمت JSON بیس۶۴ (قالب v2rayN)
        let dec = b64decode_str(body)?;
        let v: serde_json::Value = serde_json::from_str(&dec).ok()?;
        let secret_key = v["private_key"]
            .as_str()
            .or_else(|| v["secretKey"].as_str())?
            .to_string();
        let address = v["local_address"]
            .as_str()
            .or_else(|| v["address"].as_str())?
            .to_string();
        let public_key = v["peer_public_key"]
            .as_str()
            .or_else(|| v["publicKey"].as_str())?
            .to_string();
        let endpoint = v["peer_endpoint"]
            .as_str()
            .or_else(|| v["endpoint"].as_str())?
            .to_string();
        let pre_shared_key = v["pre_shared_key"]
            .as_str()
            .or_else(|| v["preSharedKey"].as_str())
            .unwrap_or("")
            .to_string();
        let reserved = v["reserved"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as u8))
                    .collect()
            })
            .unwrap_or_default();
        let mtu = v["mtu"].as_u64().unwrap_or(1420) as u32;
        Some(WireGuardInfo {
            secret_key,
            address,
            public_key,
            endpoint,
            pre_shared_key,
            reserved,
            mtu,
        })
    }
}

/// خروجی WireGuard را میسازد.
fn build_wireguard_outbound(link: &str) -> Option<serde_json::Value> {
    let i = parse_wireguard(link)?;
    let addresses: Vec<String> = i
        .address
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if i.secret_key.is_empty()
        || addresses.is_empty()
        || i.public_key.is_empty()
        || i.endpoint.is_empty()
    {
        return None;
    }

    let mut settings = serde_json::Map::new();
    settings.insert("secretKey".into(), json!(i.secret_key));
    settings.insert("address".into(), json!(addresses));

    let mut peer = serde_json::Map::new();
    peer.insert("publicKey".into(), json!(i.public_key));
    peer.insert("endpoint".into(), json!(i.endpoint));
    if !i.pre_shared_key.is_empty() {
        peer.insert("preSharedKey".into(), json!(i.pre_shared_key));
    }
    peer.insert("keepAlive".into(), json!(0));
    settings.insert("peers".into(), json!([peer]));
    settings.insert("mtu".into(), json!(i.mtu));
    if !i.reserved.is_empty() {
        settings.insert("reserved".into(), json!(i.reserved));
    }

    Some(json!({
        "protocol": "wireguard",
        "settings": settings
    }))
}

/// برچسب «proxy» و بخش آمار (stats/metrics) را به پیکربندی نهایی اضافه می‌کند.
fn finalize(outbound: serde_json::Value, http: u16, socks: u16, metrics: u16) -> serde_json::Value {
    let mut o = outbound;
    if let Some(obj) = o.as_object_mut() {
        obj.insert("tag".into(), json!("proxy"));
    }
    json!({
        "log": { "loglevel": "info" },
        "stats": {},
        "policy": {
            "system": {
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        },
        "metrics": { "listen": format!("127.0.0.1:{}", metrics) },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks,
                "protocol": "socks",
                "settings": { "udp": true }
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": http,
                "protocol": "http",
                "settings": {}
            }
        ],
        "outbounds": [o]
    })
}

/// پیکربندی حالت پروکسی: ورودی‌های SOCKS و HTTP روی پورت‌های محلی آزاد.
fn build_config(link: &str, http: u16, socks: u16, metrics: u16) -> Option<String> {
    let outbound = build_outbound(link)?;
    Some(finalize(outbound, http, socks, metrics).to_string())
}

/// پیکربندی حالت TUN: یک آداپتور مجازی که کل ترافیک ویندوز را می‌گیرد.
fn build_tun_config(link: &str, metrics: u16) -> Option<String> {
    let outbound = build_outbound(link)?;
    let mut o = outbound;
    if let Some(obj) = o.as_object_mut() {
        obj.insert("tag".into(), json!("proxy"));
    }
    let config = json!({
            "log": { "loglevel": "info" },
            "stats": {},
            "policy": {
                "system": {
                    "statsOutboundUplink": true,
                    "statsOutboundDownlink": true
                }
            },
            "metrics": { "listen": format!("127.0.0.1:{}", metrics) },
            "dns": {
                "servers": ["1.1.1.1", "8.8.8.8"]
            },
            "inbounds": [
                {
                    "tag": "tun-in",
                    "protocol": "tun",
                    "settings": {
        "name": "xray0",
        "mtu": 1500,
        "gateway": ["10.0.0.1/30", "fd00::1/126"],
        "dns": ["1.1.1.1", "8.8.8.8"],
        "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
        "autoOutboundsInterface": "auto"
    },
                    "sniffing": {
                        "enabled": true,
                        "destOverride": ["http", "tls", "quic"]
                    }
                }
            ],
            "outbounds": [o]
        });
    Some(config.to_string())
}

/* ================= پروکسی سیستم ویندوز ================= */

fn notify_wininet() {
    unsafe {
        let _ = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let _ = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }
}

/// یک پورت آزاد روی ۱۲۷٫۰٫۰٫۱ پیدا می‌کند.
fn free_port() -> Result<u16, String> {
    let l =
        TcpListener::bind("127.0.0.1:0").map_err(|e| format!("خطا در یافتن پورت آزاد: {}", e))?;
    let p = l.local_addr().map_err(|e| e.to_string())?.port();
    drop(l);
    Ok(p)
}

fn set_proxy(on: bool, ports: Option<&CorePorts>) -> Result<(), String> {
    let (key, _) = HKCU
        .create_subkey(INTERNET_SETTINGS)
        .map_err(|e| format!("خطا در بازکردن تنظیمات پروکسی: {}", e))?;

    if on {
        let ports = ports.ok_or("پورت‌های اتصال تنظیم نشده‌اند")?;
        let server = format!(
            "http=127.0.0.1:{};socks=127.0.0.1:{}",
            ports.http, ports.socks
        );
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| format!("خطا در فعال‌کردن پروکسی: {}", e))?;
        key.set_value("ProxyServer", &server)
            .map_err(|e| format!("خطا در تنظیم نشانی پروکسی: {}", e))?;
        key.set_value("ProxyOverride", &PROXY_OVERRIDE)
            .map_err(|e| format!("خطا در تنظیم استثناهای پروکسی: {}", e))?;
    } else {
        // فقط اگر خودِ ما پروکسی را روشن کرده باشیم خاموشش کن — به تنظیمات برنامه‌های دیگر دست نزن
        if let Some(ports) = ports {
            let expected = format!(
                "http=127.0.0.1:{};socks=127.0.0.1:{}",
                ports.http, ports.socks
            );
            let ours = key
                .get_value::<String, _>("ProxyServer")
                .map(|v| v == expected)
                .unwrap_or(false);
            if ours {
                key.set_value("ProxyEnable", &0u32)
                    .map_err(|e| format!("خطا در خاموش‌کردن پروکسی: {}", e))?;
            }
        }
    }

    notify_wininet();
    Ok(())
}

fn is_admin() -> bool {
    match silent(&mut Command::new("whoami")).arg("/groups").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains("S-1-16-12288"),
        Err(_) => false,
    }
}
#[tauri::command]
fn app_is_admin() -> bool {
    is_admin()
}
#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
#[tauri::command]
fn get_startup_tun() -> Option<String> {
    std::env::args().skip(1).find_map(|arg| {
        arg.strip_prefix("--tun=")
            .map(|l| l.trim_matches('"').to_string())
    })
}

/* ================= اجرای هسته ================= */

fn xray_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|_| "خطا در پیدا کردن مسیر برنامه")?;
    Ok(exe.parent().ok_or("خطا در مسیر برنامه")?.join("xray.exe"))
}

fn spawn_xray(config_path: &Path, log_path: &Path) -> Result<Child, String> {
    let xray = xray_path()?;
    if !xray.exists() {
        return Err("فایل xray.exe پیدا نشد".into());
    }
    // خروجی و خطاهای هسته داخل یک فایل لاگ می‌رود تا اگر بالا نیامد، دلیل واقعی را ببینیم
    let file = fs::File::create(log_path).map_err(|e| e.to_string())?;
    let file2 = file.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&xray);
    cmd.arg("-c").arg(config_path);
    cmd.stdout(Stdio::from(file));
    cmd.stderr(Stdio::from(file2));
    silent(&mut cmd);
    cmd.spawn().map_err(|e| format!("خطا در اجرای هسته: {}", e))
}

/// آیا کانفیگ با خودِ هسته درست است؟ (xray -test) — پیام خطای دقیق می‌دهد.
fn xray_test(config_path: &Path) -> Result<(), String> {
    let xray = xray_path()?;
    let out = silent(&mut Command::new(&xray))
        .args(["-test", "-c"])
        .arg(config_path)
        .output()
        .map_err(|e| format!("خطا در اجرای تست هسته: {}", e))?;
    let msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    )
    .trim()
    .to_string();
    if out.status.success() {
        Ok(())
    } else {
        Err(if msg.is_empty() {
            "هسته کانفیگ را نپذیرفت".into()
        } else {
            msg
        })
    }
}

/// آیا پورت محلی به اتصال پاسخ می‌دهد؟
fn tcp_ready(port: u16) -> bool {
    let addr: SocketAddr = match format!("127.0.0.1:{}", port).parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

/// منتظر بالا آمدن پورت محلی می‌ماند.
fn wait_port(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if tcp_ready(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// اگر هسته بعد از شروع از کار افتاد، دلیلش را از فایل لاگ می‌خواند.
fn child_error(mut child: Child, log_path: &Path) -> String {
    let mut reason = "هسته بالا نیامد؛ احتمالاً کانفیگ نامعتبر است".to_string();
    match child.try_wait() {
        Ok(Some(_)) => {}
        _ => {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    // کمی صبر کن تا آخرین خط‌های لاگ روی دیسک نوشته شود
    std::thread::sleep(Duration::from_millis(150));
    if let Ok(text) = fs::read_to_string(log_path) {
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(8);
        let tail = lines[start..].join("\n");
        let tail = tail.trim().to_string();
        if !tail.is_empty() {
            reason = tail;
        }
    }
    reason
}
/// آدرس Host را از endpoint به‌دست می‌آورد.
fn host_from_endpoint(endpoint: &str) -> Option<String> {
    let e = endpoint.trim().trim_end_matches('/');

    // IPv6 مثل [2001:db8::1]:51820
    if let Some(rest) = e.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(rest[..end].to_string());
    }

    // IPv4 یا دامنه مثل example.com:443
    if let Some((host, _port)) = e.rsplit_once(':') {
        return Some(host.trim_matches('[').trim_matches(']').to_string());
    }

    if !e.is_empty() {
        Some(e.to_string())
    } else {
        None
    }
}

/// آدرس سرور را از انواع کانفیگ‌ها استخراج می‌کند.
fn endpoint_host(link: &str) -> Option<String> {
    if link.starts_with("vmess://") {
        let raw = link.strip_prefix("vmess://")?;
        let text = String::from_utf8(b64decode(raw)?).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        return value["add"].as_str().map(|s| s.to_string());
    }

    if link.starts_with("trojan://") {
        return Some(parse_trojan(link)?.address);
    }

    if link.starts_with("ss://") {
        return Some(parse_ss(link)?.address);
    }

    if link.starts_with("socks5://") {
        return Some(parse_simple_proxy(link, "socks5://")?.address);
    }

    if link.starts_with("http://") {
        return Some(parse_simple_proxy(link, "http://")?.address);
    }

    if link.starts_with("wireguard://") || link.starts_with("wg://") {
        let info = parse_wireguard(link)?;
        return host_from_endpoint(&info.endpoint);
    }

    // حالت پیش‌فرض: VLESS
    Some(parse_vless(link)?.address)
}

/// آی‌پی‌های IPv4 سرور را Resolve می‌کند.
fn resolve_endpoint_ipv4(host: &str) -> Vec<String> {
    use std::net::{IpAddr, ToSocketAddrs};

    let clean = host.trim().trim_start_matches('[').trim_end_matches(']');

    let address = if clean.contains(':') {
        format!("[{}]:443", clean)
    } else {
        format!("{}:443", clean)
    };

    let mut result = Vec::new();

    if let Ok(addrs) = address.to_socket_addrs() {
        for addr in addrs {
            if let IpAddr::V4(ip) = addr.ip() {
                let value = ip.to_string();
                if !result.contains(&value) {
                    result.push(value);
                }
            }
        }
    }

    result
}

/// Gateway اصلی اینترنت را از جدول Route ویندوز پیدا می‌کند.
fn get_default_gateway() -> Option<String> {
    let output = silent(&mut Command::new("route"))
        .args(["print", "0.0.0.0"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() >= 4 && parts[0] == "0.0.0.0" {
            let gateway = parts[2];

            if gateway != "0.0.0.0" && gateway != "On-link" && gateway != "10.0.0.1" {
                return Some(gateway.to_string());
            }
        }
    }

    None
}

/// شمارهٔ Interface کارت xray0 را از خود ویندوز می‌گیرد.
fn get_interface_index(name: &str) -> Option<String> {
    let safe_name = name.replace('\'', "''");

    let script = format!(
        "(Get-NetAdapter -Name '{}' -ErrorAction Stop).ifIndex",
        safe_name
    );

    let output = silent(&mut Command::new("powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);

    text.lines()
        .find_map(|line| line.trim().parse::<u32>().ok())
        .map(|index| index.to_string())
}
/// اجرای بی‌صدای دستورهای سیستمی و بررسی موفقیت آن.
fn run_silent_command(program: &str, args: &[String]) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(args);

    let status = silent(&mut command)
        .status()
        .map_err(|e| format!("خطا در اجرای {}: {}", program, e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("دستور {} با خطا متوقف شد", program))
    }
}

/// حذف Routeهای TUN.
fn remove_tun_routes(bypasses: &[String], ifindex: Option<&str>, default_route_added: bool) {
    if default_route_added {
        let mut args = vec![
            "delete".to_string(),
            "0.0.0.0".to_string(),
            "mask".to_string(),
            "0.0.0.0".to_string(),
            "10.0.0.1".to_string(),
        ];

        if let Some(index) = ifindex {
            args.push("if".to_string());
            args.push(index.to_string());
        }

        let _ = run_silent_command("route", &args);
    }

    for ip in bypasses {
        let args = vec![
            "delete".to_string(),
            ip.clone(),
            "mask".to_string(),
            "255.255.255.255".to_string(),
        ];

        let _ = run_silent_command("route", &args);
    }
}

/// تنظیم کامل IP و Routeهای کارت TUN.
fn configure_tun_routes(link: &str) -> Result<(Vec<String>, String), String> {
    let gateway = get_default_gateway().ok_or("Gateway اصلی اینترنت پیدا نشد")?;

    let host = endpoint_host(link).ok_or("آدرس سرور کانفیگ پیدا نشد")?;

    let server_ips = resolve_endpoint_ipv4(&host);

    if server_ips.is_empty() {
        return Err("آی‌پی سرور کانفیگ Resolve نشد".into());
    }

    // دادن IP به کارت xray0
    let set_ip_args = vec![
        "interface".to_string(),
        "ip".to_string(),
        "set".to_string(),
        "address".to_string(),
        "name=xray0".to_string(),
        "static".to_string(),
        "10.0.0.1".to_string(),
        "255.255.255.252".to_string(),
    ];

    run_silent_command("netsh", &set_ip_args)?;

    std::thread::sleep(Duration::from_millis(500));

    let ifindex = get_interface_index("xray0").ok_or("ifIndex کارت xray0 پیدا نشد")?;

    let mut bypasses = Vec::new();

    // Route مستقیم برای آی‌پی سرور؛ جلوگیری از Loop
    for ip in &server_ips {
        let args = vec![
            "add".to_string(),
            ip.clone(),
            "mask".to_string(),
            "255.255.255.255".to_string(),
            gateway.clone(),
        ];

        if let Err(error) = run_silent_command("route", &args) {
            remove_tun_routes(&bypasses, Some(&ifindex), false);
            return Err(format!("Route استثنای سرور ساخته نشد: {}", error));
        }

        bypasses.push(ip.clone());
    }

    // Route پیش‌فرض از داخل TUN
    let default_args = vec![
        "add".to_string(),
        "0.0.0.0".to_string(),
        "mask".to_string(),
        "0.0.0.0".to_string(),
        "10.0.0.1".to_string(),
        "if".to_string(),
        ifindex.clone(),
        "metric".to_string(),
        "1".to_string(),
    ];

    if let Err(error) = run_silent_command("route", &default_args) {
        remove_tun_routes(&bypasses, Some(&ifindex), false);
        return Err(format!("Route پیش‌فرض TUN ساخته نشد: {}", error));
    }

    Ok((bypasses, ifindex))
}

fn start_core(
    link: &str,
    tun: bool,
    state: State<'_, AppState>,
    with_proxy: bool,
) -> Result<(), String> {
    // پورت‌های آزاد برای هر اتصال — تداخل با برنامه‌های دیگر غیرممکن می‌شود
    let l_http = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let l_socks = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let l_metrics = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let http = l_http.local_addr().map_err(|e| e.to_string())?.port();
    let socks = l_socks.local_addr().map_err(|e| e.to_string())?.port();
    let metrics = l_metrics.local_addr().map_err(|e| e.to_string())?.port();
    drop(l_http);
    drop(l_socks);
    drop(l_metrics);
    let ports = CorePorts {
        http,
        socks,
        metrics,
    };

    let config_json = if tun {
        build_tun_config(link, metrics).ok_or("لینک VLESS معتبر نیست")?
    } else {
        build_config(link, http, socks, metrics).ok_or("لینک VLESS معتبر نیست")?
    };

    let exe_dir = std::env::current_exe()
        .map_err(|_| "خطا در پیدا کردن مسیر برنامه")?
        .parent()
        .ok_or("خطا در مسیر برنامه")?
        .to_path_buf();
    let config_path = exe_dir.join("config.json");
    let log_path = exe_dir.join("nilova-core.log");

    {
        let mut file = fs::File::create(&config_path).map_err(|e| e.to_string())?;
        file.write_all(config_json.as_bytes())
            .map_err(|e| e.to_string())?;
    }

    // اعتبارسنجی کانفیگ با خودِ هسته — به‌جای پیام کلی، دلیل دقیق را می‌بینیم
    if let Err(msg) = xray_test(&config_path) {
        return Err(format!("کانفیگ نامعتبر است: {}", msg));
    }

    let mut guard = state.child.lock().map_err(|e| e.to_string())?;
    if guard.is_some() {
        return Err("از قبل متصل است".into());
    }

    let mut child = spawn_xray(&config_path, &log_path)?;

    // صبر کن تا هسته واقعاً بالا بیاید (پورت سرویس آمار)
    if !wait_port(metrics, Duration::from_secs(8)) {
        let reason = child_error(child, &log_path);
        return Err(format!("خطا در شروع اتصال: {}", reason));
    }
    // اگر هسته بعد از بالا آمدن پورت از کار افتاده باشد، اتصال را رد کن
    if let Ok(Some(_)) = child.try_wait() {
        let reason = child_error(child, &log_path);
        return Err(format!("خطا در شروع اتصال: {}", reason));
    }
    // تنظیم دستی IP و Routeهای TUN
    if tun {
                std::thread::sleep(Duration::from_millis(800));

        if let Ok(Some(_)) = child.try_wait() {
            let reason = child_error(child, &log_path);
            return Err(format!("خطا در راه‌اندازی TUN: {}", reason));
        }

        let (bypasses, ifindex) = match configure_tun_routes(link) {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("خطا در تنظیم Routeهای TUN: {}", error));
            }
        };

        *state.tun_bypasses.lock().map_err(|e| e.to_string())? = bypasses;

        *state.tun_ifindex.lock().map_err(|e| e.to_string())? = Some(ifindex);

        *state.tun_default_route.lock().map_err(|e| e.to_string())? = true;
    }

    if with_proxy {
        if let Err(e) = set_proxy(true, Some(&ports)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    }

    *state.ports.lock().map_err(|e| e.to_string())? = Some(ports);
    *guard = Some(child);
    Ok(())
}

/* ================= ابزارهای اندازه‌گیری (از طریق curl) ================= */

/// یک فرمان curl را بدون پنجره اجرا می‌کند و (موفقیت، خروجی) را برمی‌گرداند.
fn curl_run(args: &[String]) -> Result<(bool, String), String> {
    let mut cmd = Command::new("curl");
    silent(&mut cmd);
    let out = cmd
        .args(args)
        .output()
        .map_err(|e| format!("ابزار curl (curl.exe) در دسترس نیست: {}", e))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((out.status.success(), text))
}

fn proxy_arg(proxy: Option<&str>, args: &mut Vec<String>) {
    if let Some(p) = proxy {
        args.push("--proxy".into());
        args.push(p.into());
    }
}

/// مدت رفت‌وبرگشت به یک سرورِ سنجش (میلی‌ثانیه) — از داخل پروکسی یا مستقیم.
fn rtt_ms(proxy: Option<&str>, timeout: u32) -> Result<f64, String> {
    let mut args: Vec<String> = vec![
        "-4".into(),
        "-s".into(),
        "-o".into(),
        "NUL".into(),
        "--connect-timeout".into(),
        "2".into(),
        "--max-time".into(),
        timeout.to_string(),
        "-w".into(),
        "%{time_total}".into(),
    ];
    proxy_arg(proxy, &mut args);
    args.push("https://www.gstatic.com/generate_204".into());
    let (ok, out) = curl_run(&args)?;
    if !ok {
        return Err("انقضای زمان".into());
    }
    let secs: f64 = out
        .trim()
        .parse()
        .map_err(|_| "خروجی نامعتبر".to_string())?;
    Ok(secs * 1000.0)
}

/// تست واقعی یک کانفیگ: هسته را با همان کانفیگ روشن می‌کند و از داخل آن پینگ می‌گیرد.
fn run_test_one(link: &str) -> Result<serde_json::Value, String> {
    let outbound = build_outbound(link).ok_or("لینک کانفیگ نامعتبر است")?;

    // یک پورت آزاد پیدا کن
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);

    let config = json!({
        "log": { "loglevel": "none" },
        "inbounds": [
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "http",
                "settings": {}
            }
        ],
        "outbounds": [outbound]
    });

    let tmp = std::env::temp_dir().join(format!("nilova_test_{}.json", port));

    let tmp_log = std::env::temp_dir().join(format!("nilova_test_{}.log", port));

    fs::write(&tmp, config.to_string()).map_err(|e| e.to_string())?;

    let mut child = match spawn_xray(&tmp, &tmp_log) {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            let _ = fs::remove_file(&tmp_log);
            return Err(e);
        }
    };

    // صبر کن تا پورت محلی بالا بیاید؛ اگر هسته از کار افتاد دلیلش را بگو
    if !wait_port(port, Duration::from_millis(1500)) {
        let _ = child.kill();
        let _ = child.wait();

        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&tmp_log);

        return Ok(json!({
            "ok": false,
            "ms": null,
            "err": "در دسترس نیست"
        }));
    }

    let proxy = format!("http://127.0.0.1:{}", port);

    // فقط تأخیر واقعی درخواست از داخل پروکسی اندازه‌گیری می‌شود.
    let real_ms = rtt_ms(Some(&proxy), 3).ok();

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&tmp);
    let _ = fs::remove_file(&tmp_log);

    match real_ms {
        Some(ms) => Ok(json!({
            "ok": true,
            "ms": ms.round() as u64,
            "realMs": ms.round() as u64,
            "err": null
        })),

        None => Ok(json!({
            "ok": false,
            "ms": null,
            "realMs": null,
            "err": "در دسترس نیست"
        })),
    }
}
/* ================= نشانی اینترنتی ================= */

fn fetch_ip_info(proxy: Option<&str>) -> serde_json::Value {
    // ۱) ip-api.com — اطلاعات کامل کشور و شهر
    let mut base: Vec<String> = vec!["-s".into(), "--max-time".into(), "3".into()];
    proxy_arg(proxy, &mut base);

    let mut a1 = base.clone();
    a1.push("http://ip-api.com/json/".into());
    if let Ok((true, out)) = curl_run(&a1) {
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&out) {
            if j.get("status").and_then(|s| s.as_str()) == Some("success") {
                return json!({
                    "ip": j["query"].as_str().unwrap_or(""),
                    "country": j["country"].as_str().unwrap_or(""),
                    "cc": j["countryCode"].as_str().unwrap_or(""),
                    "city": j["city"].as_str().unwrap_or("")
                });
            }
        }
    }

    // ۲) ردیابی کلودفلر — معمولاً در ایران هم باز است
    let mut a2 = base.clone();
    a2.push("https://www.cloudflare.com/cdn-cgi/trace".into());
    if let Ok((true, out)) = curl_run(&a2) {
        let mut ip = "";
        let mut loc = "";
        for line in out.lines() {
            if let Some(v) = line.strip_prefix("ip=") {
                ip = v;
            }
            if let Some(v) = line.strip_prefix("loc=") {
                loc = v;
            }
        }
        if !ip.is_empty() {
            return json!({ "ip": ip, "country": "", "cc": loc, "city": "" });
        }
    }

    // ۳) ipify — فقط آی‌پی
    let mut a3 = base;
    a3.push("https://api.ipify.org?format=json".into());
    if let Ok((true, out)) = curl_run(&a3) {
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&out) {
            if let Some(ip) = j["ip"].as_str() {
                return json!({ "ip": ip, "country": "", "cc": "", "city": "" });
            }
        }
    }

    json!({ "ip": "", "country": "", "cc": "", "city": "" })
}

/* ================= آمار ترافیک (سرویس metrics خودِ Xray) ================= */

fn fetch_stats_json(port: u16) -> Option<serde_json::Value> {
    let url = format!("http://127.0.0.1:{}/debug/vars", port);
    let args: Vec<String> = vec!["-s".into(), "--max-time".into(), "3".into(), url];
    let (ok, out) = curl_run(&args).ok()?;
    if !ok {
        return None;
    }
    serde_json::from_str(&out).ok()
}

/// مقدار یک شمارندهٔ جهت‌دار خروجی را می‌خواند: outbound>>>proxy>>>traffic>>>{uplink|downlink}
fn read_stat(stats: &serde_json::Value, dir: &str) -> u64 {
    stats
        .get("stats")
        .and_then(|s| s.get("outbound"))
        .and_then(|o| o.get("proxy"))
        .and_then(|p| p.get(dir))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn stats_file() -> PathBuf {
    match std::env::var("APPDATA") {
        Ok(a) => PathBuf::from(a).join("Nilova").join("stats.json"),
        Err(_) => PathBuf::from("nilova_stats.json"),
    }
}

fn configs_file() -> PathBuf {
    match std::env::var("APPDATA") {
        Ok(a) => PathBuf::from(a).join("Nilova").join("configs.json"),
        Err(_) => PathBuf::from("nilova_configs.json"),
    }
}

#[tauri::command]
fn save_user_data(data: String) -> Result<(), String> {
    let path = configs_file();

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("خطا در ساخت پوشهٔ تنظیمات: {}", e))?;
    }

    fs::write(&path, data).map_err(|e| format!("خطا در ذخیرهٔ تنظیمات: {}", e))?;

    Ok(())
}

#[tauri::command]
fn load_user_data() -> Result<String, String> {
    match fs::read_to_string(configs_file()) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("{}".to_string()),
        Err(e) => Err(format!("خطا در خواندن تنظیمات: {}", e)),
    }
}

fn load_stats(a: &mut TrafficAcc) {
    let data = match fs::read_to_string(stats_file()) {
        Ok(d) => d,
        Err(_) => return,
    };
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
        a.today_up = v["today_up"].as_u64().unwrap_or(0);
        a.today_down = v["today_down"].as_u64().unwrap_or(0);
        a.month_up = v["month_up"].as_u64().unwrap_or(0);
        a.month_down = v["month_down"].as_u64().unwrap_or(0);
        a.total_up = v["total_up"].as_u64().unwrap_or(0);
        a.total_down = v["total_down"].as_u64().unwrap_or(0);
        a.date = v["date"].as_str().unwrap_or("").to_string();
        a.month = v["month"].as_str().unwrap_or("").to_string();
    }
}

fn save_stats(a: &TrafficAcc) {
    let v = json!({
        "date": a.date,
        "month": a.month,
        "today_up": a.today_up,
        "today_down": a.today_down,
        "month_up": a.month_up,
        "month_down": a.month_down,
        "total_up": a.total_up,
        "total_down": a.total_down
    });
    if let Some(dir) = stats_file().parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(stats_file(), v.to_string());
}

/// تاریخ امروز به شکل میلادی — از PowerShell (بدون وابستگی جدید، بدون پنجره).
fn date_str(format: &str) -> String {
    let ps_cmd = format!("Get-Date -Format '{}'", format);
    match silent(&mut Command::new("powershell"))
        .args(["-NoProfile", "-Command", ps_cmd.as_str()])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    }
}

/// اگر روز یا ماه عوض شده باشد، شمارنده‌ها را از صفر شروع کن.
fn rollover(a: &mut TrafficAcc) {
    let now = Instant::now();
    if now < a.next_rollover {
        return;
    }
    a.next_rollover = now + Duration::from_secs(60);

    let today = date_str("yyyy-MM-dd");
    let month = date_str("yyyy-MM");
    if !today.is_empty() && a.date != today {
        a.today_up = 0;
        a.today_down = 0;
        a.date = today;
    }
    if !month.is_empty() && a.month != month {
        a.month_up = 0;
        a.month_down = 0;
        a.month = month;
    }
}

/* ================= تست سرعت ================= */

/// سرعت انتقال (مگابیت بر ثانیه) از خروجی curl.
fn transfer_speed(
    proxy: Option<&str>,
    url: &str,
    write_out: &str,
    timeout: u32,
) -> Result<f64, String> {
    let mut args: Vec<String> = vec![
        "-s".into(),
        "-o".into(),
        "NUL".into(),
        "--max-time".into(),
        timeout.to_string(),
        "-w".into(),
        write_out.into(),
    ];
    proxy_arg(proxy, &mut args);
    args.push(url.into());
    let (ok, out) = curl_run(&args)?;
    if !ok {
        return Err("انقضای زمان در تست".into());
    }
    let bps: f64 = out
        .trim()
        .parse()
        .map_err(|_| "خروجی نامعتبر".to_string())?;
    Ok(bps * 8.0 / 1_000_000.0)
}

fn upload_speed(proxy: Option<&str>, bytes: usize) -> Result<f64, String> {
    let path = std::env::temp_dir().join("nilova_up.bin");
    let chunk = vec![b'x'; 1 << 20];
    let mut f = fs::File::create(&path).map_err(|e| e.to_string())?;
    for _ in 0..(bytes / (1 << 20)) {
        f.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    drop(f);

    let file = path.to_string_lossy().replace('\\', "/");
    let mut args: Vec<String> = vec![
        "-s".into(),
        "-o".into(),
        "NUL".into(),
        "--max-time".into(),
        "30".into(),
        "-w".into(),
        "%{speed_upload}".into(),
        "--data-binary".into(),
        format!("@{}", file),
    ];
    proxy_arg(proxy, &mut args);
    args.push("https://speed.cloudflare.com/__up".into());

    let res = curl_run(&args);
    let _ = fs::remove_file(&path);
    let (ok, out) = res?;
    if !ok {
        return Err("انقضای زمان در تست آپلود".into());
    }
    let bps: f64 = out
        .trim()
        .parse()
        .map_err(|_| "خروجی نامعتبر".to_string())?;
    Ok(bps * 8.0 / 1_000_000.0)
}

fn run_speedtest(mode: u32, proxy: Option<&str>) -> Result<serde_json::Value, String> {
    // در حالت TUN ترافیک مستقیم از آداپتور مجازی عبور می‌کند؛ در حالت پروکسی از پورت محلی.

    // پینگ: میانگین سه رفت‌وبرگشت
    let mut pings: Vec<f64> = Vec::new();
    for _ in 0..3 {
        if let Ok(ms) = rtt_ms(proxy, 8) {
            pings.push(ms);
        }
    }
    let ping = if pings.is_empty() {
        0.0
    } else {
        pings.iter().sum::<f64>() / pings.len() as f64
    };

    // دانلود ۲۵ مگابایت از سرور سنجش کلودفلر
    let down = transfer_speed(
        proxy,
        "https://speed.cloudflare.com/__down?bytes=25000000",
        "%{speed_download}",
        30,
    )
    .unwrap_or(0.0);

    // آپلود ۸ مگابایت به سرور سنجش کلودفلر
    let up = upload_speed(proxy, 8 * 1024 * 1024).unwrap_or(0.0);

    Ok(json!({
        "ping": ping.round() as u64,
        "down": down.round() as u64,
        "up": up.round() as u64
    }))
}

/* ================= دستورات Tauri ================= */

#[tauri::command]
async fn run_xray(link: String, state: State<'_, AppState>) -> Result<String, String> {
    start_core(&link, false, state, true)?;
    Ok("اتصال برقرار شد؛ پروکسی سیستم ویندوز روشن شد".into())
}

/// اجرای مجدد برنامه با دسترسی مدیر تا پنجرهٔ UAC ویندوز ظاهر شود.
#[cfg(windows)]
fn relaunch_elevated(link: &str) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;

    let exe = std::env::current_exe().map_err(|_| "خطا در پیدا کردن مسیر برنامه")?;
    let args = format!("--tun=\"{}\"", link.replace('"', ""));
    let wide_file: Vec<u16> = OsStr::new(&exe).encode_wide().chain(Some(0)).collect();
    let wide_verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    let wide_args: Vec<u16> = OsStr::new(&args).encode_wide().chain(Some(0)).collect();
    let wide_dir: Vec<u16> = OsStr::new("").encode_wide().chain(Some(0)).collect();
    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide_verb.as_ptr(),
            wide_file.as_ptr(),
            wide_args.as_ptr(),
            wide_dir.as_ptr(),
            5, // SW_SHOW
        )
    };
    // مقدار کمتر از ۳۲ یعنی شکست (مثلاً کاربر پنجرهٔ UAC را رد کرده است)
    if ret as usize <= 32 {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "درخواست دسترسی مدیر تأیید نشد (خطای {}). حالت TUN نیازمند تأیید پنجرهٔ ویندوز است.",
            code
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn relaunch_elevated(_link: &str) -> Result<(), String> {
    Err("حالت TUN فقط روی ویندوز پشتیبانی می‌شود".into())
}

#[tauri::command]
async fn run_tun(
    link: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    if !is_admin() {
        // اجرای مجدد با دسترسی مدیر — پنجرهٔ UAC از ویندوز خواسته می‌شود
        relaunch_elevated(&link)?;
        // نمونهٔ غیرمدیر بسته می‌شود؛ نمونهٔ مدیر با همان کانفیگ TUN را وصل می‌کند
        app.exit(0);
        return Ok("در حال دریافت دسترسی مدیر…".into());
    }
    start_core(&link, true, state, false)?;
    Ok("اتصال TUN برقرار شد؛ کل ترافیک ویندوز از طریق پروکسی عبور می‌کند".into())
}

#[tauri::command]
async fn stop_xray(state: State<'_, AppState>) -> Result<String, String> {
    // ابتدا هسته را متوقف می‌کنیم
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;

    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    drop(guard);

    // اطلاعات Routeهای TUN را کپی می‌کنیم
    let bypasses = state
        .tun_bypasses
        .lock()
        .map_err(|e| e.to_string())?
        .clone();

    let ifindex = state.tun_ifindex.lock().map_err(|e| e.to_string())?.clone();

    let default_route_added = *state.tun_default_route.lock().map_err(|e| e.to_string())?;

    // پاک‌کردن Routeهای TUN
    remove_tun_routes(&bypasses, ifindex.as_deref(), default_route_added);

    // پاک‌کردن وضعیت ذخیره‌شده
    *state.tun_bypasses.lock().map_err(|e| e.to_string())? = Vec::new();

    *state.tun_ifindex.lock().map_err(|e| e.to_string())? = None;

    *state.tun_default_route.lock().map_err(|e| e.to_string())? = false;

    *state.cached_direct_ip.lock().map_err(|e| e.to_string())? = None;

    // خاموش‌کردن Proxy ویندوز
    let ports = state.ports.lock().ok().and_then(|g| g.clone());
    let _ = set_proxy(false, ports.as_ref());

    *state.ports.lock().map_err(|e| e.to_string())? = None;

    Ok("اتصال قطع شد؛ Routeهای TUN و پروکسی پاک شدند".into())
}

/// تست پینگ واقعی یک کانفیگ.
#[tauri::command]
async fn test_one(link: String) -> Result<serde_json::Value, String> {
    run_test_one(&link)
}

/// ذخیرهٔ نشانی اینترنتی واقعی (بدون تونل) در حافظه.
#[tauri::command]
async fn cache_direct_ip(state: State<'_, AppState>) -> Result<(), String> {
    let info = fetch_ip_info(None);
    if let Ok(mut cache) = state.cached_direct_ip.lock() {
        *cache = Some(info);
    }
    Ok(())
}

/// نشانی اینترنتی از دید سایت‌ها (از داخل پروکسی) و نشانی واقعی (مستقیم).
#[tauri::command]
async fn get_ips(mode: u32, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let proxy_str = state
        .ports
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .map(|p| format!("http://127.0.0.1:{}", p.http));

    let proxy = if mode == 1 {
        None
    } else {
        proxy_str.as_deref()
    };

    // در حالت TUN، نشانی مستقیم از حافظه خوانده می‌شود
    let direct = if mode == 1 {
        state
            .cached_direct_ip
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(|| fetch_ip_info(None))
    } else {
        fetch_ip_info(None)
    };

    Ok(json!({
        "proxy": fetch_ip_info(proxy),
        "direct": direct
    }))
}

/// سرعت دانلود، آپلود و پینگ واقعی از طریق اتصال فعلی.
#[tauri::command]
async fn speed_test(mode: u32, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let proxy_str = state
        .ports
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .map(|p| format!("http://127.0.0.1:{}", p.http));
    let proxy = if mode == 1 {
        None
    } else {
        proxy_str.as_deref()
    };
    run_speedtest(mode, proxy)
}

/// دریافت متن خام یک اشتراک — استخراج لینک‌ها در خودِ رابط انجام می‌شود.
#[tauri::command]
async fn fetch_sub(url: String) -> Result<String, String> {
    let mut args: Vec<String> = vec![
        "-s".into(),
        "--max-time".into(),
        "20".into(),
        "-L".into(),
        "-A".into(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".into(),
    ];
    args.push(url);
    let (ok, out) = curl_run(&args)?;
    if !ok {
        return Err("دریافت اشتراک ناموفق بود؛ لینک در دسترس نیست یا به اینترنت نیاز دارد".into());
    }
    if out.trim().is_empty() {
        return Err("پاسخ اشتراک خالی بود".into());
    }
    Ok(out)
}

/* ================= گزارش زنده (فایل لاگ هسته) ================= */

/// مسیر فایل لاگ هسته (کنار برنامه).
fn core_log_path() -> PathBuf {
    match std::env::current_exe() {
        Ok(exe) => exe
            .parent()
            .map(|p| p.join("nilova-core.log"))
            .unwrap_or_else(|| PathBuf::from("nilova-core.log")),
        Err(_) => PathBuf::from("nilova-core.log"),
    }
}

/// خواندن خطوط تازهٔ لاگ هسته — فقط خطوطِ کاملِ جدید را برمی‌گرداند.
#[tauri::command]
fn read_core_log(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut pos = state.log_pos.lock().map_err(|e| e.to_string())?;
    let data = fs::read(core_log_path()).unwrap_or_default();
    let mut offset = *pos as usize;
    if offset > data.len() {
        offset = 0; // فایل دوباره ساخته شده (اتصال جدید)
    }
    let mut lines: Vec<String> = Vec::new();
    let mut start = offset;
    let mut i = offset;
    while i < data.len() {
        if data[i] == b'\n' {
            lines.push(
                String::from_utf8_lossy(&data[start..i])
                    .trim_end_matches('\r')
                    .to_string(),
            );
            start = i + 1;
        }
        i += 1;
    }
    *pos = start as u64;
    Ok(json!({ "offset": *pos, "lines": lines }))
}

/// پاک‌کردن نمایش لاگ: نشانگر را به انتهای فایل می‌برد تا خطوط قبلی دوباره نیایند.
#[tauri::command]
fn core_log_clear(state: State<'_, AppState>) -> Result<String, String> {
    let len = fs::metadata(core_log_path()).map(|m| m.len()).unwrap_or(0);
    *state.log_pos.lock().map_err(|e| e.to_string())? = len;
    Ok("نمایش لاگ پاک شد".into())
}

/// ذخیرهٔ یک نسخهٔ زمان‌دار از لاگ کنار برنامه.
#[tauri::command]
fn save_core_log() -> Result<String, String> {
    let path = core_log_path();
    let data = fs::read(&path).map_err(|_| "فایل لاگ وجود ندارد — اول وصل شوید".to_string())?;
    if data.is_empty() {
        return Err("لاگ خالی است".into());
    }
    let stamp = date_str("yyyyMMdd-HHmmss");
    let dest = path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("nilova-core-{}.log", stamp));
    fs::write(&dest, &data).map_err(|e| e.to_string())?;
    Ok(dest.to_string_lossy().into_owned())
}

/// آمار ترافیک مصرفی و سرعت لحظه‌ای از سرویس metrics هسته.
#[tauri::command]
async fn get_traffic(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut a = state.traffic.lock().map_err(|e| e.to_string())?;
    if !a.loaded {
        load_stats(&mut a);
        a.loaded = true;
    }
    rollover(&mut a);

    let metrics_port = state
        .ports
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|p| p.metrics));
    let stats = match metrics_port.and_then(fetch_stats_json) {
        Some(v) => v,
        None => {
            // هسته در حال اجرا نیست — نمونه‌های قبلی را هم صفر کن تا اتصال بعدی درست محاسبه شود
            a.up_speed = 0.0;
            a.down_speed = 0.0;
            a.last_up = 0;
            a.last_down = 0;
            a.last_t = None;
            return Ok(json!({
                "connected": false,
                "upSpeed": 0,
                "downSpeed": 0,
                "todayUp": a.today_up,
                "todayDown": a.today_down,
                "monthUp": a.month_up,
                "monthDown": a.month_down,
                "totalUp": a.total_up,
                "totalDown": a.total_down
            }));
        }
    };

    let up = read_stat(&stats, "uplink");
    let down = read_stat(&stats, "downlink");

    // تفاضل از نمونهٔ قبل = سرعت لحظه‌ای و مصرف جدید
    let dup = up.saturating_sub(a.last_up);
    let ddown = down.saturating_sub(a.last_down);

    let now = Instant::now();
    let (mut up_speed, mut down_speed) = (0.0, 0.0);
    if let Some(t0) = a.last_t {
        let dt = now.duration_since(t0).as_secs_f64().max(0.05);
        up_speed = dup as f64 / dt;
        down_speed = ddown as f64 / dt;
    }
    a.last_up = up;
    a.last_down = down;
    a.last_t = Some(now);
    a.up_speed = up_speed;
    a.down_speed = down_speed;

    a.today_up += dup;
    a.today_down += ddown;
    a.month_up += dup;
    a.month_down += ddown;
    a.total_up += dup;
    a.total_down += ddown;

    save_stats(&a);

    Ok(json!({
        "connected": true,
        "upSpeed": up_speed,
        "downSpeed": down_speed,
        "todayUp": a.today_up,
        "todayDown": a.today_down,
        "monthUp": a.month_up,
        "monthDown": a.month_down,
        "totalUp": a.total_up,
        "totalDown": a.total_down
    }))
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            child: Mutex::new(None),
            traffic: Mutex::new(TrafficAcc::default()),
            ports: Mutex::new(None),
            log_pos: Mutex::new(0),
            tun_bypasses: Mutex::new(Vec::new()),
            tun_default_route: Mutex::new(false),
            tun_ifindex: Mutex::new(None),
            cached_direct_ip: Mutex::new(None),
        })

        .invoke_handler(tauri::generate_handler![
            run_xray,
            run_tun,
            app_is_admin,
            get_version,
            get_startup_tun,
            stop_xray,
                   cache_direct_ip,
            test_one,
            get_ips,
            speed_test,
            fetch_sub,
            save_user_data,
            load_user_data,
            read_core_log,
            core_log_clear,
            save_core_log,
            get_traffic
        ])
        .build(tauri::generate_context!())
        .expect("خطا هنگام ساخت برنامه")
        .run(|app, event| {
            // هنگام بستن برنامه: هسته را ببند و پروکسی سیستم را خاموش کن
            if let tauri::RunEvent::Exit = event {
                let st = app.state::<AppState>();
                if let Some(mut child) = st.child.lock().ok().and_then(|mut g| g.take()) {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                let bypasses = st
                    .tun_bypasses
                    .lock()
                    .ok()
                    .map(|g| g.clone())
                    .unwrap_or_default();

                let ifindex = st.tun_ifindex.lock().ok().and_then(|g| g.clone());

                let default_route_added = st
                    .tun_default_route
                    .lock()
                    .ok()
                    .map(|g| *g)
                    .unwrap_or(false);

                remove_tun_routes(&bypasses, ifindex.as_deref(), default_route_added);

                let ports = st.ports.lock().ok().and_then(|g| g.clone());
                let _ = set_proxy(false, ports.as_ref());
            }
        });
}
