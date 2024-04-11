use alvr_common::{anyhow::Result, con_bail, ConResult, HandleTryAgain, ToCon, ALVR_NAME};
use alvr_sockets::{HANDSHAKE_PACKET_SIZE_BYTES, LOCAL_IP}; //CONTROL_PORT, 
use std::{
    net::{IpAddr, UdpSocket},
    time::Duration,
};

pub struct WelcomeSocket {
    socket: UdpSocket,
    buffer: [u8; HANDSHAKE_PACKET_SIZE_BYTES],
}

//yunjing ++ server_ip, compatibility with old 56-byte messages
impl WelcomeSocket {

    pub fn new(read_timeout: Duration) -> Result<Self> {

        //yunjing++
        let control_port = alvr_sockets::mix_read_control_port_from_file();

        let socket = UdpSocket::bind((LOCAL_IP, control_port))?; //CONTROL_PORT
        socket.set_read_timeout(Some(read_timeout))?;

        Ok(Self {
            socket,
            buffer: [0; HANDSHAKE_PACKET_SIZE_BYTES],
        })
    }

    // Returns: client IP, client hostname
    pub fn recv(&mut self) -> ConResult<(String, IpAddr, IpAddr, u8)> {
        let (size, address) = self.socket.recv_from(&mut self.buffer).handle_try_again()?;

        if (size >= 56) //yunjing modify 56 -> 61 // && size <= HANDSHAKE_PACKET_SIZE_BYTES
            && &self.buffer[..ALVR_NAME.len()] == ALVR_NAME.as_bytes()
            && self.buffer[ALVR_NAME.len()..16].iter().all(|b| *b == 0)
        {
            let mut protocol_id_bytes = [0; 8];
            protocol_id_bytes.copy_from_slice(&self.buffer[16..24]);
            let received_protocol_id = u64::from_le_bytes(protocol_id_bytes);

            if received_protocol_id != alvr_common::protocol_id() {
                con_bail!("Found incompatible client! Upgrade or downgrade\nExpected protocol ID {}, Found {received_protocol_id}",
                alvr_common::protocol_id());
            }

            let mut hostname_bytes = [0; 32];
            hostname_bytes.copy_from_slice(&self.buffer[24..56]);
            let hostname = std::str::from_utf8(&hostname_bytes)
                .to_con()?
                .trim_end_matches('\x00')
                .to_owned();

            let mut server_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
            if size >= 60 { // 60
                let server_ip_bytes = &self.buffer[56..60];
                let server_ip_bytes_array = [server_ip_bytes[0], server_ip_bytes[1], server_ip_bytes[2], server_ip_bytes[3]];
                let ipv4_addr = std::net::Ipv4Addr::from(server_ip_bytes_array);
                server_ip = std::net::IpAddr::V4(ipv4_addr);
            }
            //con_bail!("[yj_dbg] recv size:{}, Hostname: {}, IP: {}, SERVER_IP: {}", size, hostname, address.ip(), server_ip); // print failed msg, debug only

            let mut is_heartbeat = 0;
            if size >= 61 { // 61
                is_heartbeat = self.buffer[60];
            }

            Ok((hostname, address.ip(), server_ip, is_heartbeat))
        } else if &self.buffer[..16] == b"\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00ALVR"
            || &self.buffer[..5] == b"\x01ALVR"
        {
            con_bail!("Found old client. Please upgrade")
        } else {
            // Unexpected packet.
            // Note: no need to check for v12 and v13, not found in the wild anymore
            con_bail!("Found unrelated packet during discovery")
        }
    }
}
