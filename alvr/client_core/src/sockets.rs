use alvr_common::{info, anyhow::Result, ALVR_NAME};
use alvr_sockets::{CONTROL_PORT, LOCAL_IP, HANDSHAKE_PACKET_SIZE_BYTES};
use std::net::{Ipv4Addr, UdpSocket};

pub struct AnnouncerSocket {
    socket: UdpSocket,
    packet: [u8; 61], // yunjing 56->60 ++ server_ip 4 bytes, is_heartbeat 1 byte
    hostname_len: usize,
    unicast_ip: Ipv4Addr, // yunjing ++
    control_port: u16, // yunjing ++
    is_heartbeat: u8, // yunjing ++
}

impl AnnouncerSocket {
    pub fn new(hostname: &str, server_ip: Ipv4Addr, control_port: u16, is_heartbeat: u8) -> Result<Self> {
        let actual_port = if control_port == 0 { CONTROL_PORT } else { control_port };
        let socket = UdpSocket::bind((LOCAL_IP, actual_port))?;
        socket.set_broadcast(true)?;

        let mut packet = [0; HANDSHAKE_PACKET_SIZE_BYTES]; // yunjing 56->60 ++ server_ip 4 bytes
        packet[0..ALVR_NAME.len()].copy_from_slice(ALVR_NAME.as_bytes());
        packet[16..24].copy_from_slice(&alvr_common::protocol_id().to_le_bytes());
        let hostname_len = hostname.len();
        packet[24..24 + hostname_len].copy_from_slice(hostname.as_bytes());

        //yunjing ++ server_ip to packet, rust start..end not include end 60
        packet[56..60].copy_from_slice(&server_ip.octets());

        //yunjing ++ add is_heartbeat
        packet[60] = is_heartbeat;

        info!("[yj_dbg] new UdpSocket - hostname {}, server_ip {}, control_port {}", hostname, server_ip, actual_port);

        Ok(Self { socket, packet, hostname_len, unicast_ip: server_ip, control_port: actual_port, is_heartbeat })
    }

    pub fn broadcast(&self) -> Result<()> {
        // info!("[yj_dbg] Broadcasting packet: {:?}", self.packet); //no info! no log!

        //yunjing modify
        // Check if server_ip is not all zeros
        if self.unicast_ip != Ipv4Addr::new(0, 0, 0, 0) {
            info!("[yj_dbg] Send unicast to server_ip {} {}", self.unicast_ip, self.control_port);
            self.socket.send_to(&self.packet, (self.unicast_ip, self.control_port))?;
        } else {
            info!("[yj_dbg] Send broadcast to ctrl_port {}", self.control_port);
            self.socket.send_to(&self.packet, (Ipv4Addr::BROADCAST, self.control_port))?;
        }

        Ok(())
    }

    pub fn get_print_str(&self) -> String {
        let alvr_name = String::from_utf8_lossy(&self.packet[0..ALVR_NAME.len()]);
        let protocol_id = u64::from_le_bytes(self.packet[16..24].try_into().unwrap());
        let hostname = String::from_utf8_lossy(&self.packet[24..24 + self.hostname_len]);
        let server_ip = std::net::Ipv4Addr::new(self.packet[56], self.packet[57], self.packet[58], self.packet[59]);

        format!(
            "ALVR_NAME: {}, Protocol ID: {}, Hostname: {}, Server IP: {}, Control Port: {}",
            alvr_name, protocol_id, hostname, server_ip, self.control_port
        )
    }
}
