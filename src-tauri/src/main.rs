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
}

const PROXY_OVERRIDE: &str = "<local>";
const INTERNET_SETTINGS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

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

/// خروجی VLESS را با تمام تنظیمات امنیتی و انتقال می‌سازد (مشترک پروکسی و TUN).
fn build_outbound(link: &str) -> Option<serde_json::Value> {
    let i = parse_vless(link)?;
    let port: u16 = i.port.parse().ok()?;

    let mut stream = serde_json::Map::new();
    stream.insert("network".into(), json!(i.network));
    let security = if i.security.is_empty() { "none" } else { i.security.as_str() };
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
        let server_name = if !i.sni.is_empty() { i.sni.clone() } else { i.host.clone() };
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
        let _ = InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

/// یک پورت آزاد روی ۱۲۷٫۰٫۰٫۱ پیدا می‌کند.
fn free_port() -> Result<u16, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("خطا در یافتن پورت آزاد: {}", e))?;
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
        let server = format!("http=127.0.0.1:{};socks=127.0.0.1:{}", ports.http, ports.socks);
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| format!("خطا در فعال‌کردن پروکسی: {}", e))?;
        key.set_value("ProxyServer", &server)
            .map_err(|e| format!("خطا در تنظیم نشانی پروکسی: {}", e))?;
        key.set_value("ProxyOverride", &PROXY_OVERRIDE)
            .map_err(|e| format!("خطا در تنظیم استثناهای پروکسی: {}", e))?;
    } else {
        // فقط اگر خودِ ما پروکسی را روشن کرده باشیم خاموشش کن — به تنظیمات برنامه‌های دیگر دست نزن
        if let Some(ports) = ports {
            let expected = format!("http=127.0.0.1:{};socks=127.0.0.1:{}", ports.http, ports.socks);
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
    std::env::args()
        .skip(1)
        .find_map(|arg| arg.strip_prefix("--tun=").map(|l| l.trim_matches('"').to_string()))
}

/* ================= اجرای هسته ================= */

fn xray_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|_| "خطا در پیدا کردن مسیر برنامه")?;
    Ok(exe
        .parent()
        .ok_or("خطا در مسیر برنامه")?
        .join("xray.exe"))
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

fn start_core(link: &str, tun: bool, state: State<'_, AppState>, with_proxy: bool) -> Result<(), String> {
    // پورت‌های آزاد برای هر اتصال — تداخل با برنامه‌های دیگر غیرممکن می‌شود
    let l_http = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let l_socks = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let l_metrics = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let http = l_http.local_addr().map_err(|e| e.to_string())?.port();
    let socks = l_socks.local_addr().map_err(|e| e.to_string())?.port();
    let metrics = l_metrics.local_addr().map_err(|e| e.to_string())?.port();
    drop(l_http); drop(l_socks); drop(l_metrics);
    let ports = CorePorts { http, socks, metrics };

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
   // در حالت TUN فقط بسته‌شدن واقعی Xray را خطا حساب کن
    if tun {
    // فرصت بده آداپتور TUN کامل ساخته شود
    std::thread::sleep(Duration::from_millis(1500));

    // اگر Xray واقعاً بسته شده باشد، خطای واقعی لاگ را نمایش بده
    if let Ok(Some(_)) = child.try_wait() {
        let reason = child_error(child, &log_path);
        return Err(format!("خطا در راه‌اندازی TUN: {}", reason));
    }
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
        "-s".into(),
        "-o".into(),
        "NUL".into(),
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
    let secs: f64 = out.trim().parse().map_err(|_| "خروجی نامعتبر".to_string())?;
    Ok(secs * 1000.0)
}

/// تست واقعی یک کانفیگ: هسته را با همان کانفیگ روشن می‌کند و از داخل آن پینگ می‌گیرد.
fn run_test_one(link: &str) -> Result<serde_json::Value, String> {
    let info = parse_vless(link).ok_or("لینک کانفیگ نامعتبر است")?;
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

    let tmp = std::env::temp_dir().join("nilova_test.json");
    let tmp_log = std::env::temp_dir().join("nilova_test.log");
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
if !wait_port(port, Duration::from_secs(2)) {
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

// مرحله اول: بررسی سلامت واقعی کانفیگ از داخل تونل Xray
let real_ms = rtt_ms(Some(&proxy), 5).ok();

// مرحله دوم: TCP Ping مستقیم شبیه TCPing در کلاینت‌های دیگر
let tcp_ms: Option<f64> = if real_ms.is_some() {
    use std::net::ToSocketAddrs;

    let endpoint = format!("{}:{}", info.address, info.port);

    match endpoint.as_str().to_socket_addrs() {
        Ok(mut addrs) => {
            addrs.next().and_then(|socket_addr| {
                let started = Instant::now();

                TcpStream::connect_timeout(
                    &socket_addr,
                    Duration::from_millis(1500),
                )
                .ok()?;

                Some(started.elapsed().as_secs_f64() * 1000.0)
            })
        }
        Err(_) => None,
    }
} else {
    None
};

// اولویت نمایش:
// ۱) TCP Ping اگر موجود باشد
// ۲) Real Delay اگر TCP Ping ممکن نباشد
let best = tcp_ms.or(real_ms);



    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&tmp);
    let _ = fs::remove_file(&tmp_log);

    match best {
    Some(ms) => Ok(json!({
        "ok": true,
        "ms": ms.round() as u64,
        "tcpMs": tcp_ms.map(|v| v.round() as u64),
        "realMs": real_ms.map(|v| v.round() as u64),
        "err": null
    })),

    None => Ok(json!({
        "ok": false,
        "ms": null,
        "tcpMs": null,
        "realMs": null,
        "err": "در دسترس نیست"
    })),
  }

}

/* ================= نشانی اینترنتی ================= */

fn fetch_ip_info(proxy: Option<&str>) -> serde_json::Value {
    // ۱) ip-api.com — اطلاعات کامل کشور و شهر
    let mut base: Vec<String> = vec!["-s".into(), "--max-time".into(), "8".into()];
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
    let args: Vec<String> = vec![
        "-s".into(),
        "--max-time".into(),
        "3".into(),
        url,
    ];
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
        Ok(a) => PathBuf::from(a)
            .join("Nilova")
            .join("configs.json"),
        Err(_) => PathBuf::from("nilova_configs.json"),
    }
}

#[tauri::command]
fn save_user_data(data: String) -> Result<(), String> {
    let path = configs_file();

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .map_err(|e| format!("خطا در ساخت پوشهٔ تنظیمات: {}", e))?;
    }

    fs::write(&path, data)
        .map_err(|e| format!("خطا در ذخیرهٔ تنظیمات: {}", e))?;

    Ok(())
}

#[tauri::command]
fn load_user_data() -> Result<String, String> {
    match fs::read_to_string(configs_file()) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok("{}".to_string())
        }
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
fn transfer_speed(proxy: Option<&str>, url: &str, write_out: &str, timeout: u32) -> Result<f64, String> {
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
    let bps: f64 = out.trim().parse().map_err(|_| "خروجی نامعتبر".to_string())?;
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
    let bps: f64 = out.trim().parse().map_err(|_| "خروجی نامعتبر".to_string())?;
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
async fn run_tun(link: String, state: State<'_, AppState>, app: tauri::AppHandle) -> Result<String, String> {
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
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    drop(guard);
    let ports = state.ports.lock().ok().and_then(|g| g.clone());
    let _ = set_proxy(false, ports.as_ref());
    *state.ports.lock().map_err(|e| e.to_string())? = None;
    Ok("اتصال قطع شد؛ پروکسی سیستم ویندوز خاموش شد".into())
}

/// تست پینگ واقعی یک کانفیگ.
#[tauri::command]
async fn test_one(link: String) -> Result<serde_json::Value, String> {
    run_test_one(&link)
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
    Ok(json!({
        "proxy": fetch_ip_info(proxy),
        "direct": fetch_ip_info(None)
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
        })
                     .invoke_handler(tauri::generate_handler![
    run_xray,
    run_tun,
    app_is_admin,
    get_version,
    get_startup_tun,
    stop_xray,
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
                let ports = st.ports.lock().ok().and_then(|g| g.clone());
                let _ = set_proxy(false, ports.as_ref());
            }
        });
}
