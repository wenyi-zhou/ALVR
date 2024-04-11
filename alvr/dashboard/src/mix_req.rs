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
    os::windows::process::CommandExt,
    thread,
    format,
    io::prelude::*,
    sync::Mutex,
};
use serde_json::{Value, json};
use alvr_common::{debug, info, error};
use reqwest;
use regex::Regex;
use winreg::enums::*;
use winreg::RegKey;
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
    let parent_pid = alvr_sockets::mix_get_u16_from_args("--parent_pid").unwrap_or(0) as u32;
    if parent_pid == 0 {
        return;
    }
    thread::spawn(move || {
        loop {
            if !is_pid_running(parent_pid) {
                info!("Parent PID {} no longer exists. Exiting...", parent_pid);

                //in box
                alvr_sockets::mix_try_clean_chlid_process(false);

                //not in box
                let mut killpids = String::from("--killpids=");
                unsafe {
                    //kill res_app first
                    if let Some(res_app_pid) = M_RES_APP_PID {
                        if res_app_pid > 0 {
                            killpids.push_str(&format!("{},", res_app_pid));
                        }
                    }
                    //then kill vrmonitor
                    if let Some(vrmonitor_pid) = M_VRMONITOR_PID {
                        if vrmonitor_pid > 0 {
                            killpids.push_str(&format!("{},", vrmonitor_pid));
                        }
                    }
                }
                if killpids != "--killpids=" {
                    killpids.pop(); // Remove the trailing comma
                    let _ = Command::new("starter.exe")
                        .arg(killpids.clone())
                        .spawn();
                    info!("Kill child processes: {}", killpids);
                }

                thread::sleep(Duration::from_millis(500));
                std::process::exit(0);
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
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

    // return Some("container.exe".to_string());

    // Open SteamVR registry key
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let steamvr_key = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Steam App 250820", KEY_READ);
    if let Ok(steamvr_key) = steamvr_key {
        //InstallLocation C:\Program Files (x86)\Steam\steamapps\common\SteamVR
        //UninstallString: "C:\Program Files (x86)\Steam\steam.exe" steam://uninstall/250820
        let install_location: String = steamvr_key.get_value("InstallLocation").unwrap();
        if !install_location.is_empty() {
            let vrmonitor_path = format!("{}\\bin\\win64\\vrmonitor.exe", install_location);
            if Path::new(&vrmonitor_path).exists() {
                return Some(vrmonitor_path);
            }
        }
    }
    
    {
        // Check if vrmonitor.exe exists in the specified path
        let vrmonitor_path = "C:\\SteamVR\\bin\\win64\\vrmonitor.exe";
        if Path::new(vrmonitor_path).exists() {
            return Some(vrmonitor_path.to_string());
        } else {
            info!("SteamVR is not installed. Please install SteamVR.");
            return None;
        }
    }
}

pub fn try_kill_prev_steamvr()
{
    let (_, _, _, _, boxie_index, _) = alvr_sockets::mix_read_args_from_file();
    if boxie_index > 0 {
        return;
    }

    // thread::spawn(move || { //no kill self by mistake
    let process_names = vec!["DLPLuckyGo.exe", "DLPRender.exe", "vrmonitor.exe", "vrserver.exe"]; //先kill应用 再kill vrmonitor 最后kill vrserver，SteamVR才不会弹异常对话框
    let mut process_exists;
    for process_name in process_names {
        let output = Command::new("tasklist")
            .arg("/FI")
            .arg(&format!("IMAGENAME eq {}", process_name))
            .output()
            .expect("Failed to execute tasklist command");

        let process_output = String::from_utf8_lossy(&output.stdout);
        process_exists = process_output.contains(process_name);
        if process_exists {
            //debug!("[yj_dbg] kill prev steamvr not in sandboxie [{process_output}]");
            Command::new("taskkill")
                .args(&["/F", "/IM", process_name])
                .output()
                .ok();
                debug!("Killed process: {}", process_name);
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    // });
}

pub fn launch_steamvr_with_path(path: &str) {
    /*
    CREATE_NEW_CONSOLE: 新进程有一个新的控制台，而不是继承其父进程的控制台。
    CREATE_NEW_PROCESS_GROUP: 新进程是新进程组的根进程。新进程组包括所有由新进程创建的子进程，但不包括所有继承的进程。
    CREATE_NO_WINDOW: 新进程没有控制台窗口。如果新进程从其父进程继承了控制台的话，那么它的控制台窗口就不会显示。
    CREATE_UNICODE_ENVIRONMENT: 指示由lpEnvironment参数指定的环境块包含Unicode字符。否则，字符串假定为ANSI字符。
    CREATE_SUSPENDED: 新进程的主线程将创建为挂起的，且不会运行。要开始执行挂起线程，必须使用ResumeThread函数。
    CREATE_SEPARATE_WOW_VDM: 当启动16位Windows程序时，如果设置了这个标志，那么它将在单独的Virtual DOS Machine (VDM)中运行。
    CREATE_SHARED_WOW_VDM: 与CREATE_SEPARATE_WOW_VDM相反，这个标志指示16位Windows程序在共享的VDM中运行。这是默认的行为。
    */

    //yunjing modify
    // let child = Command::new("cmd")
    //     .args(["/C", "start", "steam://rungameid/250820"])
    //     .creation_flags(CREATE_NO_WINDOW)
    //     .spawn()
    //     .ok();

    // let output = Command::new("D:\\Program Files (x86)\\Steam\\steamapps\\common\\SteamVR\\bin\\win64\\vrmonitor.exe") //C:\\SteamVR\\bin\\win64\\vrmonitor.exe vrstartup.exe
    //     .creation_flags(CREATE_NO_WINDOW)
    //     .spawn();

    // let output = Command::new("wmic")
    //     .args(["process", "call", "create", "C:\\SteamVR\\bin\\win64\\vrmonitor.exe"]) //vrstartup.exe
    //     .spawn();

    let path_clone = path.to_string();
    thread::spawn(move || {

        // //Check prev steamvr running
        // let process_names = vec!["vrmonitor.exe", "vrserver.exe"];
        // let mut prev_exists = false;
        // let mut process_exists = true;
        // let mut counter = 0;
        // while process_exists && counter < 100 {
        //     for process_name in &process_names {
        //         let output = Command::new("tasklist")
        //             .arg("/FI")
        //             .arg(&format!("IMAGENAME eq {}", process_name))
        //             .output()
        //             .expect("Failed to execute tasklist command");

        //         process_exists = String::from_utf8_lossy(&output.stdout).contains(process_name);
        //         if process_exists {
        //             prev_exists = true;
        //             debug!("[yj_dbg] wait for {} to exit...", process_name);
        //             thread::sleep(Duration::from_millis(100));
        //         } else {
        //             break;
        //         }
        //     }
        //     counter += 1;
        // }
        // if prev_exists {
        //     thread::sleep(Duration::from_millis(1000));
        // }


        let (control_port, _, _, api_port, boxie_index, _) = alvr_sockets::mix_read_args_from_file();


        if boxie_index > 0 {

            std::thread::sleep(std::time::Duration::from_millis(200)); //Sandboxie Start.exe imidiately may failed, so sleep 

            if let Some(sandboxie_path) = alvr_sockets::get_sandboxie_path_from_default() {
                let mut cmd =Command::new(sandboxie_path.clone())
                .arg(format!("/box:{}", boxie_index))
                .arg("open_with")
                //.arg(res_app.clone())
                // .arg("C:\\SteamVR\\bin\\win64\\vrmonitor.exe")
                .arg(path_clone.clone())
                .arg(format!("--control_port={} --api_port={} --boxie_index={}", control_port, api_port, boxie_index))
                .spawn()
                .expect("Failed to spawn new process");
        
                let cmd_string = format!(
                    "{:?} /box:{} open_with {} --control_port={} --api_port={} --boxie_index={}",
                    sandboxie_path, boxie_index, path_clone, control_port, api_port, boxie_index
                );
                info!("Command: {}", cmd_string);

                let status = cmd.wait().expect("Failed to wait for child process");   

                if status.success() {
                    info!("Success to open vrmonitor in Sandboxie {}.", boxie_index);
                } else {
                    info!("Failed to open vrmonitor in Sandboxie {}.", boxie_index);
                }
            } else {
                info!("Sandboxie is not installed.");
            }

        } else {

            // Launch SteamVR on Windows
            let output2 = Command::new(&path_clone)
                .arg(format!("--control_port={} --api_port={}", control_port, api_port))
                .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();

            debug!("[yj_dbg] start steamvr: {} --control_port={} --api_port={}", &path_clone, control_port, api_port);

            match output2 {
                Ok(child) => {
                    unsafe {
                        M_VRMONITOR_PID = Some(child.id());
                    }
                    debug!("[yj_dbg] Spawned child process with id {}", child.id());
                }
                Err(e) => {
                    debug!("[yj_dbg] Failed to spawn child process: {}", e);
                }
            }

        }

    });
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

    let (_, _, _, _, boxie_index, res_app) = alvr_sockets::mix_read_args_from_file();

    info!("{} Launching...", res_app);

    if !res_app.is_empty() {

        if boxie_index > 0 {

            std::thread::sleep(std::time::Duration::from_millis(200)); //Sandboxie Start.exe imidiately may failed, so sleep 

            if let Some(sandboxie_path) = alvr_sockets::get_sandboxie_path_from_default() {

                let current_exe_path = env::current_exe().expect("Failed to get current executable path");
                let mut starter_exe_path = current_exe_path.clone();
                starter_exe_path.set_file_name("starter.exe");
                let starter_exe_path_str = starter_exe_path.display().to_string();

                let mut cmd =Command::new(sandboxie_path.clone())
                .arg(format!("/box:{}", boxie_index))
                .arg("open_with")
                //.arg(res_app.clone())
                .arg(starter_exe_path_str.clone())
                .arg(format!("--start_res_app=\"{}\"", res_app.clone()))
                .arg(format!("--boxie_index={}", boxie_index))
                .spawn()
                .expect("Failed to spawn new process");
        
                let cmd_string = format!(
                    "{:?} /box:{} open_with {} --start_res_app=\"{}\" --boxie_index={}",
                    sandboxie_path, boxie_index, starter_exe_path_str, res_app, boxie_index
                );
                info!("Command: {}", cmd_string);
    
                let status = cmd.wait().expect("Failed to wait for child process");   
    
                if status.success() {
                    info!("Success to open res_app in Sandboxie {}.", boxie_index);
                } else {
                    info!("Failed to open res_app in Sandboxie {}.", boxie_index);
                }
            } else {
                info!("Sandboxie is not installed.");
            }

        }else{
            
            //let output = Command::new("cmd") //can't get child process id
                // .args(&["/C", &res_app])

	        // let output = Command::new(res_app.clone())
            //     .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
            //     .stdout(Stdio::null())
            //     .stderr(Stdio::null())
            //     .spawn();

            //prompt: res_app是这种格式：'C:\XR\DLPDesigner+V2.8.0.230704\x64\DLPLuckyGo.exe' "D:\DLP_VRP\半条被子.vrp" --MulInst 1 代码改成切割出参数运行，切割出第一个是exe，后面的是参数，遇到单引号或双引号 第二个单引号或双引号结束作为一个exe或参数，否则按空格切割参数
            let re = Regex::new(r#"'[^']*'|"[^"]*"|\S+"#).unwrap();
            let mut matches = re.find_iter(res_app.as_str()).map(|m| m.as_str().trim_matches('"').trim_matches('\'').to_string()).collect::<Vec<_>>();
            let exe_path = matches.remove(0);
            let output = Command::new(exe_path.clone())
                .args(&matches)
                .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();

            debug!("[yj_dbg] start res_app exe:[{}], args:{:?}", exe_path, matches);

            match output {
                Ok(child) => {
                    unsafe {
                        if let Some(pid) = M_RES_APP_PID {
                            if pid != 0 {
                                let _ = Command::new("starter.exe")
                                    .arg(pid.to_string())
                                    .spawn();
                                info!("Kill prev res_app processes: {}", pid);
                            }
                        }

                        M_RES_APP_PID = Some(child.id());
                    }
                    debug!("[yj_dbg] Spawned res_app process with id {}", child.id());
                }
                Err(e) => {
                    debug!("[yj_dbg] Failed to spawn child process: {}", e);
                }
            }

        }


    }

}