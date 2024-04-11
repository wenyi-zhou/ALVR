use std::{
    env,
    fs,
    fs::OpenOptions,
    fs::create_dir_all,
    path::Path,
    time::Duration,
    process::Stdio,
    // process,
    // process::exit,
    process::Command,
    thread,
    format,
    io::prelude::*,
    sync::Mutex,
};

use serde_json::{Value, json};
use alvr_common::{debug, info, error};
use reqwest;
use regex::Regex;
use chrono::prelude::*;
use lazy_static::lazy_static;

static mut M_VRMONITOR_PID: Option<u32> = None;
static mut M_RES_APP_PID: Option<u32> = None;


//----------------------- config -----------------------
static MIX_CONF_PATH: &str = "mix.json";

lazy_static! {
    pub static ref MIX_SESSION: MixSession = MixSession::new();
}

pub struct MixSession {
    initialized: Mutex<bool>,
    report_lost_hmd_seconds: Mutex<u64>,
    is_write_stat_to_logfile: Mutex<bool>,
    server_url: Mutex<Option<String>>,
}

impl MixSession {
    pub fn new() -> MixSession {
        MixSession {
            initialized: Mutex::new(false),
            report_lost_hmd_seconds: Mutex::new(0),
            is_write_stat_to_logfile: Mutex::new(false),
            server_url: Mutex::new(None),
        }
    }

    fn read_config(&self) {
        let exe_path = env::current_exe().unwrap();
        let exe_dir = exe_path.parent().unwrap();
        let session_path = exe_dir.join(MIX_CONF_PATH);

        debug!("Config path: {}", session_path.display());

        let session_content = fs::read_to_string(session_path).unwrap_or_default();
        let session_json: Value = serde_json::from_str(&session_content).unwrap_or_default();

        let report_lost_hmd_seconds = session_json["render_server"]["report_lost_hmd_seconds"].as_u64().unwrap_or(60);
        let is_write_stat_to_logfile = session_json["render_server"]["is_write_stat_to_logfile"].as_bool().unwrap_or(false);
        let server_url = session_json["render_server"]["url"].as_str().map(|s| s.to_string());

        debug!("  report_lost_hmd_seconds: {}", report_lost_hmd_seconds);
        debug!("  is_write_stat_to_logfile: {}", is_write_stat_to_logfile);
        debug!("  server_url: {}", server_url.as_deref().unwrap_or("None"));

        let mut global_report_lost_hmd_seconds = self.report_lost_hmd_seconds.lock().unwrap();
        *global_report_lost_hmd_seconds = report_lost_hmd_seconds;

        let mut global_is_write_stat_to_logfile = self.is_write_stat_to_logfile.lock().unwrap();
        *global_is_write_stat_to_logfile = is_write_stat_to_logfile;

        let mut global_server_url = self.server_url.lock().unwrap();
        *global_server_url = server_url;
    }

    fn initialize(&self) {
        let mut initialized = self.initialized.lock().unwrap();
        if !*initialized {
            self.read_config();
            *initialized = true;
        }
    }

    pub fn get_report_lost_hmd_seconds(&self) -> u64 {
        self.initialize();

        let report_lost_hmd_seconds = self.report_lost_hmd_seconds.lock().unwrap();
        *report_lost_hmd_seconds
    }

    pub fn get_is_write_stat_to_logfile(&self) -> bool {
        self.initialize();

        let is_write_stat_to_logfile = self.is_write_stat_to_logfile.lock().unwrap();
        *is_write_stat_to_logfile
    }

    pub fn get_server_url(&self) -> String {
        self.initialize();

        let server_url = self.server_url.lock().unwrap();
        server_url.clone().unwrap_or_else(|| String::from("http://localhost:35101"))
    }
}

//----------------------- backend -----------------------
fn get_req_pid() -> u32 {
    let parent_pid = alvr_sockets::mix_get_u16_from_args("--parent_pid").unwrap_or(0) as u32;
    let mut pid = std::process::id();
    if parent_pid > 0 {
        pid = parent_pid;
    }
    pid
}

fn is_pid_running(pid: u32) -> bool {
    let output = Command::new("tasklist")
        .args(&["/FI", &format!("PID eq {}", pid)])
        .output()
        .expect("Failed to execute tasklist command");

    let output_str = String::from_utf8_lossy(&output.stdout);
    let process_list: Vec<&str> = output_str.split('\n').collect();

    for process in process_list {
        if process.contains(&pid.to_string()) {
            return true;
        }
    }

    false
}

pub fn monitor_parent_process() {
    // TODO wait coding
}

//async
pub fn send_steamvr_status_update(status: &str) -> Result<(), reqwest::Error> {
    info!("send_steamvr_status_update");

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;

    let payload = json!({
        "metadata": {},
        "payload": {
            "pid": get_req_pid(),
            "status": status //pending connected streaming aborted
        }
    });

    let server_url = MIX_SESSION.get_server_url();
    let url = format!("{}/render/reportTask", server_url);

    info!("[yj_dbg] url : {} {}", url, status); // Print the URL

    let response = match client.post(&url).json(&payload).send() {
        Ok(response) => response,
        Err(e) => {
            error!("[yj_dbg] Failed to send request: {}", e);
            return Err(e);
        }
    };

    match response.status() {
        reqwest::StatusCode::OK => info!("[yj_dbg] Request was successful"),
        s => info!("[yj_dbg] Received response status: {:?}", s),
    }

    match response.text() {
        Ok(text) => info!("[yj_dbg] Received response text: {}", text),
        Err(e) => error!("[yj_dbg] Failed to read response text: {}", e),
    }

    Ok(())
}

//----------------------- write logs -----------------------
pub fn log_str2file(event_string: &str) {
    // 获取当前 exe 所在的目录
    let exe_path = env::current_exe().unwrap();
    let exe_dir = exe_path.parent().unwrap();

    // 拼接 "/logs/" 到目录路径
    let log_dir = exe_dir.join("logs");

    // 检查目录是否存在，如果不存在则创建
    if !log_dir.exists() {
        create_dir_all(&log_dir).unwrap();
    }

    // 获取当前日期并格式化为字符串
    let now = Local::now();
    let date = now.format("%Y-%m-%d").to_string();

    // 创建文件名，包括路径和日期
    let filename = log_dir.join(format!("{}.log", date));

    // 使用 OpenOptions 打开文件，如果文件不存在则创建
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&filename)
        .unwrap();

    // 将事件数据写入文件
    if let Err(e) = writeln!(file, "{}", event_string) {
        eprintln!("Couldn't write to file: {}", e);
    }
}

//----------------------- vrmonitor.exe -----------------------
pub fn get_steamvr_path_from_config() -> Option<String> {
    let exe_path = env::current_exe().unwrap();
    let exe_dir = exe_path.parent().unwrap();
    let session_path = exe_dir.join(MIX_CONF_PATH);

    debug!("Config path: {}", session_path.display());

    let session_content = fs::read_to_string(session_path).ok()?;

    let session_json: Value = serde_json::from_str(&session_content).ok()?;

    let steamvr_path = session_json["render_server"]["steamvr_path"].as_str().unwrap_or("");

    // 添加条件判断
    if steamvr_path.len() < 3 {
        return None;
    }

    debug!("get_steamvr_path_from_config: {}", steamvr_path);

    return Some(steamvr_path.to_string());
}

pub fn get_steamvr_path_from_default() -> Option<String> {
    return None;
}

pub fn try_kill_prev_steamvr() {
    // TODO wait coding
    return;
}


pub fn launch_steamvr_with_path(path: &str) {
    // TODO wait coding
    return;
}

pub fn try_launch_steamvr() {
    let steamvr_path = get_steamvr_path_from_config();
    if let Some(path) = steamvr_path {
        // Use the path from the config
        launch_steamvr_with_path(&path);
    } else {
        let default_path = get_steamvr_path_from_default();

        if let Some(path) = default_path {
            // Use the default path
            launch_steamvr_with_path(&path);
        } else {
            // SteamVR is not installed
            info!("SteamVR is not installed. Please install SteamVR.");
        }
    }
}

pub fn try_launch_res_app() {
    return;
}