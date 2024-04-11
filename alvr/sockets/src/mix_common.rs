use crate::CONTROL_PORT;
use alvr_common::{info};

pub fn mix_get_ports(control_port_in: u16, media_port_in: u16, audio_port_in: u16) -> (u16, u16, u16) {
    let control_port;
    let media_port;
    let audio_port;
    
    if control_port_in > 0 {
        control_port = control_port_in;
    }else{
        control_port = CONTROL_PORT;
    }
    
    if media_port_in > 0 {
        media_port = media_port_in;
    }else{
        media_port = control_port + 1;
    }
    
    if audio_port_in > 0 {
        audio_port = audio_port_in;
    }else{
        audio_port = control_port - 1;
    }

    info!("[yj_dbg] [sockets] Args - control_port: {:?}, media_port: {:?}, audio_port: {:?}", control_port, media_port, audio_port);
    
    (control_port, media_port, audio_port)
}
