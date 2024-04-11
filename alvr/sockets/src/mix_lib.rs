use crate::CONTROL_PORT;
use std::{
    env,
    // fs,
    // fs::File,
    // io::Write,
    // io::Read,
    net::TcpListener,
    // path::Path,
    path::PathBuf,
    // time::Duration,
    // process::Stdio,
    process::Command,
    process::exit,
};
use ini::Ini;
use alvr_common::{debug, info, error};
// use port_check::is_port_reachable;
// use regex::Regex;
use rand::Rng;
use winreg::{enums::*, RegKey};
use winapi::um::winnt::KEY_READ;
use winapi::um::winuser::{MessageBoxW, MB_ICONERROR, MB_OK};

pub const MIX_DEF_API_PORT_BEGIN: u16 = 38082;//18082;
pub const MIX_DEF_VRSERVER_PORT_BEGIN: u16 = 57062;

//----------------------- args -----------------------
pub fn mix_get_u16_from_args(arg_name: &str) -> Option<u16> {
    let mut port: Option<u16> = None;
    let args: Vec<String> = env::args().collect();
    // debug!("[yj_dbg] [sockets] Args: {:?}", args);

    for arg in args {
        let parts: Vec<&str> = arg.split('=').collect();
        if parts[0] == arg_name {
            port = parts.get(1).and_then(|s| s.parse::<u16>().ok());
        }
    }

    // let pattern = format!(r".*--{}=('.*?'|\S+)", arg_name);
    // let regex = Regex::new(&pattern).expect("Invalid regex pattern");
    // for arg in args {
    //     if let Some(capture) = regex.captures(&arg) {
    //         if let Some(value) = capture.get(1) {
    //             let trimmed_value = value.as_str().trim_matches(|c| c == '\'' || c == ' ');
    //             port = trimmed_value.parse::<u16>().ok();
    //             break;
    //         }
    //     }
    // }


    //info!("[yj_dbg] [sockets] Args - {}: {:?}", arg_name, port);
    port
}

pub fn get_string_from_args(arg_name: &str) -> Option<String> {
    let mut value: Option<String> = None;
    let args: Vec<String> = env::args().collect();

    for arg in args {
        let parts: Vec<&str> = arg.split('=').collect();
        if parts[0] == arg_name {
            value = parts.get(1).map(|s| s.to_string());
        }
    }

    //info!("[yj_dbg] [sockets] Args - {}: {:?}", arg_name, value);
    value
}

// pub fn get_control_port_from_args() -> u16 {
//     let control_port = mix_get_u16_from_args("--control_port").unwrap_or(CONTROL_PORT);
//     control_port
// }

// pub fn get_stream_port_from_args() -> u16 {
//     let control_port = get_control_port_from_args();
//     let stream_port = control_port + 1;
//     info!("[yj_dbg] Args [sockets] - control_port: {:?} +1 is stream_port: {:?}", control_port, stream_port);
//     stream_port
// }

pub fn get_available_port(start_port: u16) -> Option<u16> {
    let max_attempts = 128;
    let end_port = start_port + max_attempts;

    let mut rng = rand::thread_rng();
    let port = rng.gen_range(start_port..=end_port);

    if TcpListener::bind(("127.0.0.1", port)).is_ok() {
        Some(port)
    } else {
        None
    }

    // if !is_port_reachable("127.0.0.1", port) {
    //     return Some(port);
    // }
}

pub fn get_sandboxie_path_from_default() -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let sandboxie_key = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie", KEY_READ);

    if let Ok(sandboxie_key) = sandboxie_key {
        // let install_location: String = sandboxie_key.get_value("InstallLocation").unwrap();
        // let start_path = format!("{}Start.exe", install_location);
        let start_path: String = sandboxie_key.get_value("DisplayIcon")
            .unwrap_or_else(|_error| {
                // Show message box with error message
                let message = "Please install Sandboxie.";
                let title = "Sandboxie Not Found";
                unsafe {
                    MessageBoxW(
                        std::ptr::null_mut(),
                        message.encode_utf16().collect::<Vec<u16>>().as_ptr(),
                        title.encode_utf16().collect::<Vec<u16>>().as_ptr(),
                        MB_OK | MB_ICONERROR,
                    );
                }
                String::new()
            });
        return Some(start_path);
    } else {
        let sandboxie_plus_key = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie-Plus_is1", KEY_READ);

        if let Ok(sandboxie_plus_key) = sandboxie_plus_key {
            let install_location: String = sandboxie_plus_key.get_value("InstallLocation").unwrap();
            let start_path = format!("{}Start.exe", install_location);
            return Some(start_path);
        } else {
            // Show message box with error message
            let message = "Please install Sandboxie.";
            let title = "Sandboxie Not Found";
            unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    message.encode_utf16().collect::<Vec<u16>>().as_ptr(),
                    title.encode_utf16().collect::<Vec<u16>>().as_ptr(),
                    MB_OK | MB_ICONERROR,
                );
            }

            return None;
        }
    }
}

fn get_boxie_index() -> u16 {
    let mut boxie_index = mix_get_u16_from_args("--boxie_index").unwrap_or(0);

    //DLP not support open in sandboxie yet
    let res_app = get_string_from_args("--res_app").unwrap_or(String::new());
    if res_app.contains("DLPLuckyGo.exe") || res_app.contains("DLPReader.exe") {
        debug!("[yj_dbg] DLP exe, set boxie_index 0");//DLP not support open in sandboxie yet
        boxie_index = 0;
    }

    boxie_index
}

//for read and read from boxie
pub fn get_run_file_path() -> PathBuf {
    let file_path = env::temp_dir(); //vrserver.exe also call
    // info!("[yj_dbg] pid:{}, tmp path: {}", std::process::id(), file_path.display());

    let exe_path = env::current_exe().unwrap();
    // // let file_path = exe_path.parent().unwrap();
    // debug!("[yj_dbg] exe_path:{}", exe_path.display());

    let boxie_index = get_boxie_index();

    if boxie_index > 0 || exe_path.file_name().unwrap().to_str().unwrap().contains("Dashboard.exe") {
        let run_cfg_path = file_path.join(format!("mix_run_{}.ini", boxie_index));
        return run_cfg_path;
    }

    // if env::temp_dir().to_str().unwrap().contains("\\current\\") { //in boxie
    //     return file_path.join("mix_run.ini")
    // } else {
    //     return file_path.join("mix_run_0.ini") //when vrserver not in boxie
    // }

    let ini_file = file_path.join("mix_run_x.ini");//in boxie
    if ini_file.exists() {
        return ini_file;
    }else{
        return file_path.join("mix_run_0.ini")//out boxie
    }
}

//for write
pub fn get_run_file_path_x(boxie_index: u16) -> PathBuf {
    let file_path = env::temp_dir();
    let run_cfg_path = file_path.join(format!("mix_run_{}.ini", boxie_index));
    run_cfg_path
}

//for write to boxie
pub fn get_run_file_path_in_boxie() -> PathBuf {
    let file_path = env::temp_dir();
    let run_cfg_path = file_path.join("mix_run_x.ini");
    run_cfg_path
}

pub fn mix_try_clean_chlid_process(delete_files: bool)
{
    let boxie_index = get_boxie_index();
    //start another self, for copy ini file to sandboxie
    if boxie_index > 0 {
        if let Some(sandboxie_path) = get_sandboxie_path_from_default() {

            //https://github.com/sandboxie-plus/sandboxie-docs/blob/main/Content/StartCommandLine.md
            {//clean boxie procs job
                std::thread::sleep(std::time::Duration::from_millis(100));
                let status = Command::new(sandboxie_path.clone())
                .arg(format!("/box:{}", boxie_index))
                .arg("/terminate")
                .spawn()
                .expect("Failed to spawn new process")
                .wait()
                .expect("Failed to wait for child process");

                if status.success() {
                    info!("Success to clean procs in Sandboxie {}.", boxie_index);
                } else {
                    info!("Failed to clean procs in Sandboxie {}.", boxie_index);
                }
            }


            if delete_files {//clean boxie files job
                std::thread::sleep(std::time::Duration::from_millis(100));
                let status = Command::new(sandboxie_path.clone())
                .arg(format!("/box:{}", boxie_index))
                .arg("delete_sandbox") //delete_sandbox_silent delete_sandbox
                .spawn()
                .expect("Failed to spawn new process")
                .wait()
                .expect("Failed to wait for child process");

                if status.success() {
                    info!("Success to clean files in Sandboxie {}.", boxie_index);
                } else {
                    info!("Failed to clean files in Sandboxie {}.", boxie_index);
                }
            }
            
        } else {
            info!("Sandboxie is not installed.");
        }
    }else{
        info!("Not in Sandboxie.");

    }
}


pub fn mix_write_args_to_file() -> (u16, u16, u16, u16, u16, String) {
    let args: Vec<String> = env::args().collect();
    debug!("[yj_dbg] [sockets] Args: [{:?}]", args);

    let write_to_boxie = mix_get_u16_from_args("--write_to_boxie").unwrap_or(0);
    let res_app = get_string_from_args("--res_app").unwrap_or(String::new());
    // let res_app = res_app.replace("\\\"", "\"");
    //let res_app = res_app.replace('\'', "\"");

    let boxie_index = get_boxie_index();
    mix_try_clean_chlid_process(true);

    let path = get_run_file_path_in_boxie();
    if path.exists() {
        match std::fs::remove_file(path) {
            Ok(_) => println!("mix_run_x.ini removed successfully"),
            Err(e) => println!("failed to remove mix_run_x.ini: {}", e),
        }
    }

    if boxie_index > 0 {//write boxie ini job
        if let Some(sandboxie_path) = get_sandboxie_path_from_default() {
            let current_exe = env::current_exe().expect("Failed to get current executable path");

            std::thread::sleep(std::time::Duration::from_millis(100));
            let status = Command::new(sandboxie_path.clone())
            .arg(format!("/box:{}", boxie_index))
            .arg("open_with")
            .arg(format!("{}", current_exe.to_str().unwrap()))
            .arg(format!("--write_to_boxie={}", boxie_index))
            .spawn()
            .expect("Failed to spawn new process")
            .wait()
            .expect("Failed to wait for child process");

            if status.success() {
                info!("Success to write ini in Sandboxie {}.", boxie_index);
            } else {
                info!("Failed to write ini in Sandboxie {}.", boxie_index);
            }
        }
    }

    //do copy ini file to sandboxie
    if write_to_boxie > 0 {
        let src_file_path = get_run_file_path_x(write_to_boxie);
        let dest_file_path = get_run_file_path_in_boxie();

        if let Err(err) = std::fs::copy(&src_file_path, &dest_file_path) {
            info!("Failed to copy file: {}", err);
        }
        exit(0);
    }

    let control_port = mix_get_u16_from_args("--control_port").unwrap_or(CONTROL_PORT);
    let mut media_port = mix_get_u16_from_args("--media_port").unwrap_or(CONTROL_PORT + 1);
    let mut audio_port = mix_get_u16_from_args("--audio_port").unwrap_or(CONTROL_PORT - 1);
    if 0 == media_port && control_port > 0 {
        media_port = control_port + 1;
    }
    if 0 == audio_port && control_port > 0 {
        audio_port = control_port - 1;
    }

    // let api_port = match get_available_port(MIX_DEF_API_PORT_BEGIN) {
    //     Some(port) => {
    //         println!("[yj_dbg] [sockets] Args - Available api port: {}", port);
    //         port
    //     }
    //     None => {
    //         println!("[yj_dbg] [sockets] Args - Error: No available api port found.");
    //         MIX_DEF_API_PORT_BEGIN
    //     }
    // };
    let api_port = MIX_DEF_API_PORT_BEGIN + boxie_index;

    let mut config = Ini::new();
    config.with_section(Some("mix".to_owned())) // Set "mix" as the section name
        .set("control_port", control_port.to_string())
        .set("media_port", media_port.to_string())
        .set("audio_port", audio_port.to_string())
        .set("api_port", api_port.to_string())
        .set("boxie_index", boxie_index.to_string())
        .set("res_app", res_app.clone());
    
    info!("control_port: {}, media_port: {}, audio_port: {}, api_port: {}, boxie_index: {}, res_app: {}", control_port, media_port, audio_port, api_port, boxie_index, res_app.clone());
    
    let run_cfg_path = get_run_file_path_x(boxie_index);
    info!("Writing parameters to file: {}", run_cfg_path.display());
    if let Err(e) = config.write_to_file(&run_cfg_path) {
        error!("Failed to write parameters to file: {}", e);
    }
    
    (control_port, media_port, audio_port, api_port, boxie_index, res_app)
}

pub fn mix_read_args_from_file() -> (u16, u16, u16, u16, u16, String) {
    let run_cfg_path = get_run_file_path();
    let config = match Ini::load_from_file(&run_cfg_path) {
        Ok(config) => config,
        Err(e) => {
            error!("[yj_dbg] pid:{}, Failed to load ini file: {}, {}", std::process::id(), run_cfg_path.display(), e);
            return (CONTROL_PORT, CONTROL_PORT + 1, CONTROL_PORT - 1, MIX_DEF_API_PORT_BEGIN, 0, String::new());
        }
    };
    //info!("Success to load ini file: {}", run_cfg_path.display());

    let control_port = config.get_from::<String>(Some("mix".to_owned()), "control_port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(CONTROL_PORT);
    let media_port = config.get_from::<String>(Some("mix".to_owned()), "media_port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(CONTROL_PORT + 1);
    let audio_port = config.get_from::<String>(Some("mix".to_owned()), "audio_port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(CONTROL_PORT - 1);
    let api_port = config.get_from::<String>(Some("mix".to_owned()), "api_port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(MIX_DEF_API_PORT_BEGIN);
    let boxie_index = config.get_from::<String>(Some("mix".to_owned()), "boxie_index")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let res_app = config.get_from::<String>(Some("mix".to_owned()), "res_app")
        .map(|s| {
            //debug!("res_app[{:?}] length[{}]", s, s.len());
            s.to_string()
        })
        // .map(|s| s.replace("\\'", "'"))
        .unwrap_or(String::new());

    //info!("[yj_dbg] [sockets] Read parameters from file {}: control_port: {:?}, media_port: {:?}, audio_port: {:?}, api_port: {:?}, boxie_index: {:?}, res_app: {:?}",
    //    run_cfg_path.display(), control_port, media_port, audio_port, api_port, boxie_index, res_app);

    (control_port, media_port, audio_port, api_port, boxie_index, res_app)
}

pub fn mix_read_control_port_from_file() -> u16 {
    debug!("[yj_dbg] pid:{}, mix_read_control_port_from_file()", std::process::id());
    let (control_port, _, _, _, _, _) = mix_read_args_from_file();
    control_port
}

pub fn mix_read_api_port_from_file() -> u16 {
    debug!("[yj_dbg] pid:{}, mix_read_api_port_from_file()", std::process::id());
    let (_, _, _, api_port, _, _) = mix_read_args_from_file();
    api_port
}

pub fn mix_read_boxie_index_from_file() -> u16 {
    debug!("[yj_dbg] pid:{}, mix_read_boxie_index_from_file()", std::process::id());
    let (_, _, _, _, boxie_index, _) = mix_read_args_from_file();
    boxie_index
}
