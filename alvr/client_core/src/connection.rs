#![allow(clippy::if_same_then_else)]

use crate::{
    decoder::{self, DECODER_INIT_CONFIG},
    logging_backend::{LogMirrorData, LOG_CHANNEL_SENDER},
    platform,
    sockets::AnnouncerSocket,
    statistics::StatisticsManager,
    storage::Config,
    ClientCoreEvent, EVENT_QUEUE, IS_ALIVE, IS_RESUMED, IS_STREAMING, STATISTICS_MANAGER,
};
use alvr_audio::AudioDevice;
use alvr_common::{
    debug, error, glam::UVec2, info, warn, AnyhowToCon, ConResult, ConnectionError, LazyMutOpt,
    ToCon, ALVR_VERSION,
};
use alvr_packets::{
    ClientConnectionResult, ClientControlPacket, ClientStatistics, Haptics, ServerControlPacket,
    StreamConfigPacket, Tracking, VideoPacketHeader, VideoStreamingCapabilities, AUDIO, HAPTICS,
    STATISTICS, TRACKING, VIDEO,
};
use alvr_session::{settings_schema::Switch, SessionConfig};
use alvr_sockets::{
    ControlSocketSender, PeerType, ProtoControlSocket, StreamSender, StreamSocketBuilder,
    KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT,
};
use serde_json as json;
use std::{
    collections::HashMap,
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};
use std::net::Ipv4Addr;
// use encoding_rs::GBK;

#[cfg(target_os = "android")]
use crate::audio;
#[cfg(not(target_os = "android"))]
use alvr_audio as audio;

const INITIAL_MESSAGE: &str = concat!(
    "Searching for streamer...\n",
    "Open ALVR on your PC then click \"Trust\"\n",
    "next to the client entry",
);
const NETWORK_UNREACHABLE_MESSAGE: &str = "Cannot connect to the internet";
// const INCOMPATIBLE_VERSIONS_MESSAGE: &str = concat!(
//     "Streamer and client have\n",
//     "incompatible types.\n",
//     "Please update either the app\n",
//     "on the PC or on the headset",
// );
const STREAM_STARTING_MESSAGE: &str = "The stream will begin soon\nPlease wait...";
const SERVER_RESTART_MESSAGE: &str = "The streamer is restarting\nPlease wait...";
const SERVER_DISCONNECTED_MESSAGE: &str = "The streamer has disconnected.";
const CONNECTION_TIMEOUT_MESSAGE: &str = "Connection timeout.";

const DISCOVERY_RETRY_PAUSE: Duration = Duration::from_millis(500);
const RETRY_CONNECT_MIN_INTERVAL: Duration = Duration::from_secs(1);
const CONNECTION_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const HANDSHAKE_ACTION_TIMEOUT: Duration = Duration::from_secs(2);
const STREAMING_RECV_TIMEOUT: Duration = Duration::from_millis(500);

const MAX_UNREAD_PACKETS: usize = 10; // Applies per stream

static DISCONNECT_SERVER_NOTIFIER: LazyMutOpt<mpsc::Sender<()>> = alvr_common::lazy_mut_none();

pub static CONTROL_SENDER: LazyMutOpt<ControlSocketSender<ClientControlPacket>> =
    alvr_common::lazy_mut_none();
pub static TRACKING_SENDER: LazyMutOpt<StreamSender<Tracking>> = alvr_common::lazy_mut_none();
pub static STATISTICS_SENDER: LazyMutOpt<StreamSender<ClientStatistics>> =
    alvr_common::lazy_mut_none();

fn set_hud_message(message: &str) {
    let message = format!(
        "ALVR v{}\nhostname: {}\nIP: {}\n\n{message}",
        *ALVR_VERSION,
        Config::load().hostname,
        platform::local_ip(),
    );
    // let message = format!(
    //     "\u{4e91}\u{5883}\u{4e91}\u{6e32}\u{67b6}\u{7ec8}\u{7aef} v{}\nhostname: {}\nIP: {}\n\n{message}", //云境云渲染终端
    //     *ALVR_VERSION,
    //     Config::load().hostname,
    //     platform::local_ip(),
    // );

    // let gbk_bytes = GBK.encode(&message).0;
    // let utf8_message = std::str::from_utf8(&gbk_bytes).unwrap();
    // let message = utf8_message.to_string();

    // let bytes = message.as_bytes();
    // let (decoded_message, _, _) = GBK.decode(bytes);
    // let message = decoded_message.to_string();

    EVENT_QUEUE
        .lock()
        .push_back(ClientCoreEvent::UpdateHudMessage(message));
}

pub fn connection_lifecycle_loop(
    recommended_view_resolution: UVec2,
    supported_refresh_rates: Vec<f32>,
    server_ip: Ipv4Addr, // yunjing ++
    control_port_in: u16, // yunjing ++
    media_port_in: u16, // yunjing ++
    audio_port_in: u16, // yunjing ++
) {
    set_hud_message(INITIAL_MESSAGE);


    //yunjing++
    info!("[yj_dbg] connection_lifecycle_loop in");
    let (control_port, media_port, audio_port) = alvr_sockets::mix_get_ports(control_port_in, media_port_in, audio_port_in);
    let config = Config::load();
    let hostname = config.hostname.clone();
    let mut tick = 0;
    let mut is_connected = false;


    while IS_ALIVE.value() {
        if IS_RESUMED.value() {
            if let Err(e) =
                connection_pipeline(recommended_view_resolution, supported_refresh_rates.clone(), server_ip, control_port, media_port, audio_port)
            {
                let message = format!("Connection error:\n{e}\nCheck the PC for more details");
                set_hud_message(&message);
                error!("Connection error: {e}");
            }else{
                is_connected = true;
            }
        } else {
            debug!("Skip try connection because the device is sleeping");
        }
        

        //yunjing++ udp heartbeat
        if is_connected {
            if tick % 5 == 0 { //send udp heartbeat every n seconds
                info!("[yj_dbg] AnnouncerSocket send udp heartbeat");
                let _hb_socket = match AnnouncerSocket::new(&hostname, server_ip, control_port, 1).to_con() {
                    Ok(socket) => {
                        // info!("[yj_dbg] connection_lifecycle_loop in, udp broadcast success");
                        let broadcast_result = socket.broadcast();
                        if let Err(e) = &broadcast_result {
                            warn!("[yj_dbg] Broadcast heartbeat error: {e:?}");
                            // set_hud_message(NETWORK_UNREACHABLE_MESSAGE);
                            // set_hud_message(INITIAL_MESSAGE);
                        } else {
                            let message = broadcast_result.unwrap();
                            info!("[yj_dbg] heartbeat success, message: {:?}", message);
                        }
    
                        socket
                    },
                    Err(_e2) => {
                        error!("[yj_dbg] Failed to create AnnouncerSocket");
                        return;
                    }
                };
                tick = 0;
            }
            tick += 1;
        }


        thread::sleep(CONNECTION_RETRY_INTERVAL);
    }
}

fn connection_pipeline(
    recommended_view_resolution: UVec2,
    supported_refresh_rates: Vec<f32>,
    server_ip: Ipv4Addr, // yunjing ++
    control_port: u16, // yunjing ++
    media_port: u16, // yunjing ++
    _audio_port: u16, // yunjing ++
) -> ConResult {
    let (mut proto_control_socket, server_ip) = {
        let config = Config::load();

        /* yunjing add comment: 
            1. Discovery: PC listens to UDP 9943 - HMD broadcast
            2. Control port: HMD listen to TCP 9943 - PC TCP random 5 digits
            3. SteamVR streaming port: PC UDP 9944 - HMD also UDP 9944
        */

        let announcer_socket = AnnouncerSocket::new(&config.hostname, server_ip, control_port, 0).to_con()?;
        let listener_socket =
            alvr_sockets::get_server_listener(HANDSHAKE_ACTION_TIMEOUT, control_port).to_con()?;

        let print_str = announcer_socket.get_print_str();
        info!("[yj_dbg] connection_pipeline in, udp broadcast {}", print_str);

        loop {

            if !IS_ALIVE.value() {
                info!("[yj_dbg] onnection aborted");
                return Ok(());
            }

            if let Err(e) = announcer_socket.broadcast() {
                warn!("Broadcast error: {e:?}");

                set_hud_message(NETWORK_UNREACHABLE_MESSAGE);

                thread::sleep(RETRY_CONNECT_MIN_INTERVAL);

                set_hud_message(INITIAL_MESSAGE);

                return Ok(());
            }else{
                info!("[yj_dbg] send broadcast success");
            }

            info!("[yj_dbg] tcp listen control_port:{}", control_port);
            if let Ok(pair) = ProtoControlSocket::connect_to(
                DISCOVERY_RETRY_PAUSE,
                PeerType::Server(&listener_socket),
                control_port,
            ) {
                break pair;
            }

            // info!("[yj_dbg] tcp listen end, retrying in {:?}", DISCOVERY_RETRY_PAUSE);
        }
    };

    let (disconnect_sender, disconnect_receiver) = mpsc::channel();
    *DISCONNECT_SERVER_NOTIFIER.lock() = Some(disconnect_sender);

    struct DropGuard;
    impl Drop for DropGuard {
        fn drop(&mut self) {
            *DISCONNECT_SERVER_NOTIFIER.lock() = None;
        }
    }
    let _connection_drop_guard = DropGuard;

    let microphone_sample_rate = AudioDevice::new_input(None)
        .unwrap()
        .input_sample_rate()
        .unwrap();

    proto_control_socket
        .send(&ClientConnectionResult::ConnectionAccepted {
            client_protocol_id: alvr_common::protocol_id(),
            display_name: platform::device_model(),
            server_ip,
            streaming_capabilities: Some(VideoStreamingCapabilities {
                default_view_resolution: recommended_view_resolution,
                supported_refresh_rates,
                microphone_sample_rate,
            }),
        })
        .to_con()?;
    let config_packet =
        proto_control_socket.recv::<StreamConfigPacket>(HANDSHAKE_ACTION_TIMEOUT)?;

    let settings = {
        let mut session_desc = SessionConfig::default();
        session_desc
            .merge_from_json(&json::from_str(&config_packet.session).to_con()?)
            .to_con()?;
        session_desc.to_settings()
    };

    let negotiated_config =
        json::from_str::<HashMap<String, json::Value>>(&config_packet.negotiated).to_con()?;

    let view_resolution = negotiated_config
        .get("view_resolution")
        .and_then(|v| json::from_value(v.clone()).ok())
        .unwrap_or(UVec2::ZERO);
    let refresh_rate_hint = negotiated_config
        .get("refresh_rate_hint")
        .and_then(|v| v.as_f64())
        .unwrap_or(60.0) as f32;
    let game_audio_sample_rate = negotiated_config
        .get("game_audio_sample_rate")
        .and_then(|v| v.as_u64())
        .unwrap_or(44100) as u32;

    let streaming_start_event = ClientCoreEvent::StreamingStarted {
        view_resolution,
        refresh_rate_hint,
        settings: Box::new(settings.clone()),
    };

    *STATISTICS_MANAGER.lock() = Some(StatisticsManager::new(
        settings.connection.statistics_history_size,
        Duration::from_secs_f32(1.0 / refresh_rate_hint),
        if let Switch::Enabled(config) = settings.headset.controllers {
            config.steamvr_pipeline_frames
        } else {
            0.0
        },
    ));

    let (mut control_sender, mut control_receiver) = proto_control_socket
        .split(STREAMING_RECV_TIMEOUT)
        .to_con()?;

    match control_receiver.recv(HANDSHAKE_ACTION_TIMEOUT) {
        Ok(ServerControlPacket::StartStream) => {
            info!("Stream starting");
            set_hud_message(STREAM_STARTING_MESSAGE);
        }
        Ok(ServerControlPacket::Restarting) => {
            info!("Server restarting");
            set_hud_message(SERVER_RESTART_MESSAGE);
            return Ok(());
        }
        Err(e) => {
            info!("Server disconnected. Cause: {e}");
            set_hud_message(SERVER_DISCONNECTED_MESSAGE);
            return Ok(());
        }
        _ => {
            info!("Unexpected packet");
            set_hud_message("Unexpected packet");
            return Ok(());
        }
    }

    let stream_socket_builder = StreamSocketBuilder::listen_for_server(
        Duration::from_secs(1),
        media_port, //settings.connection.stream_port, //yunjing modify
        settings.connection.stream_protocol,
        settings.connection.client_send_buffer_bytes,
        settings.connection.client_recv_buffer_bytes,
    )
    .to_con()?;

    if let Err(e) = control_sender.send(&ClientControlPacket::StreamReady) {
        info!("Server disconnected. Cause: {e:?}");
        set_hud_message(SERVER_DISCONNECTED_MESSAGE);
        return Ok(());
    }

    let mut stream_socket = stream_socket_builder.accept_from_server(
        server_ip,

         // yunjing modify
        // settings.connection.stream_port,
        media_port,
        
        settings.connection.packet_size as _,
        HANDSHAKE_ACTION_TIMEOUT,
    )?;
    info!("[yj_dbg] Connected to server ip: {server_ip} stream port: {}", media_port); // yunjing modify

    {
        let config = &mut *DECODER_INIT_CONFIG.lock();

        config.max_buffering_frames = settings.video.max_buffering_frames;
        config.buffering_history_weight = settings.video.buffering_history_weight;
        config.options = settings.video.mediacodec_extra_options;
    }

    let mut video_receiver =
        stream_socket.subscribe_to_stream::<VideoPacketHeader>(VIDEO, MAX_UNREAD_PACKETS);
    let game_audio_receiver = stream_socket.subscribe_to_stream(AUDIO, MAX_UNREAD_PACKETS);
    let tracking_sender = stream_socket.request_stream(TRACKING);
    let mut haptics_receiver =
        stream_socket.subscribe_to_stream::<Haptics>(HAPTICS, MAX_UNREAD_PACKETS);
    let statistics_sender = stream_socket.request_stream(STATISTICS);

    // Important: To make sure this is successfully unset when stopping streaming, the rest of the
    // function MUST be infallible
    IS_STREAMING.set(true);
    *CONTROL_SENDER.lock() = Some(control_sender);
    *TRACKING_SENDER.lock() = Some(tracking_sender);
    *STATISTICS_SENDER.lock() = Some(statistics_sender);

    let (log_channel_sender, log_channel_receiver) = mpsc::channel();
    if let Switch::Enabled(filter_level) = settings.logging.client_log_report_level {
        *LOG_CHANNEL_SENDER.lock() = Some(LogMirrorData {
            sender: log_channel_sender,
            filter_level,
        });
    }

    EVENT_QUEUE.lock().push_back(streaming_start_event);

    let video_receive_thread = thread::spawn(move || {
        let mut stream_corrupted = false;
        while IS_STREAMING.value() {
            let data = match video_receiver.recv(STREAMING_RECV_TIMEOUT) {
                Ok(data) => data,
                Err(ConnectionError::TryAgain(_)) => continue,
                Err(ConnectionError::Other(_)) => return,
            };
            let Ok((header, nal)) = data.get() else {
                return;
            };

            if let Some(stats) = &mut *STATISTICS_MANAGER.lock() {
                stats.report_video_packet_received(header.timestamp);
            }

            if header.is_idr {
                stream_corrupted = false;
            } else if data.had_packet_loss() {
                stream_corrupted = true;
                if let Some(sender) = &mut *CONTROL_SENDER.lock() {
                    sender.send(&ClientControlPacket::RequestIdr).ok();
                }
                warn!("Network dropped video packet");
            }

            if !stream_corrupted || !settings.connection.avoid_video_glitching {
                if !decoder::push_nal(header.timestamp, nal) {
                    stream_corrupted = true;
                    if let Some(sender) = &mut *CONTROL_SENDER.lock() {
                        sender.send(&ClientControlPacket::RequestIdr).ok();
                    }
                    warn!("Dropped video packet. Reason: Decoder saturation")
                }
            } else {
                if let Some(sender) = &mut *CONTROL_SENDER.lock() {
                    sender.send(&ClientControlPacket::RequestIdr).ok();
                }
                warn!("Dropped video packet. Reason: Waiting for IDR frame")
            }
        }
    });

    let game_audio_thread = if let Switch::Enabled(config) = settings.audio.game_audio {
        let device = AudioDevice::new_output(None, None).to_con()?;

        thread::spawn(move || {
            alvr_common::show_err(audio::play_audio_loop(
                Arc::clone(&IS_STREAMING),
                device,
                2,
                game_audio_sample_rate,
                config.buffering,
                game_audio_receiver,
            ));
        })
    } else {
        thread::spawn(|| ())
    };

    let microphone_thread = if matches!(settings.audio.microphone, Switch::Enabled(_)) {
        let device = AudioDevice::new_input(None).to_con()?;

        let microphone_sender = stream_socket.request_stream(AUDIO);

        thread::spawn(move || {
            while IS_STREAMING.value() {
                match audio::record_audio_blocking(
                    Arc::clone(&IS_STREAMING),
                    microphone_sender.clone(),
                    &device,
                    1,
                    false,
                ) {
                    Ok(()) => break,
                    Err(e) => {
                        error!("Audio record error: {e}");

                        continue;
                    }
                }
            }
        })
    } else {
        thread::spawn(|| ())
    };

    let haptics_receive_thread = thread::spawn(move || {
        while IS_STREAMING.value() {
            let data = match haptics_receiver.recv(STREAMING_RECV_TIMEOUT) {
                Ok(packet) => packet,
                Err(ConnectionError::TryAgain(_)) => continue,
                Err(ConnectionError::Other(_)) => return,
            };
            let Ok(haptics) = data.get_header() else {
                return;
            };

            EVENT_QUEUE.lock().push_back(ClientCoreEvent::Haptics {
                device_id: haptics.device_id,
                duration: haptics.duration,
                frequency: haptics.frequency,
                amplitude: haptics.amplitude,
            });
        }
    });

    let control_send_thread = thread::spawn(move || {
        let mut keepalive_deadline = Instant::now();

        #[cfg(target_os = "android")]
        let battery_manager = platform::android::BatteryManager::new();
        #[cfg(target_os = "android")]
        let mut battery_deadline = Instant::now();

        while IS_STREAMING.value() && IS_RESUMED.value() && IS_ALIVE.value() {
            if let (Ok(packet), Some(sender)) = (
                log_channel_receiver.recv_timeout(STREAMING_RECV_TIMEOUT),
                &mut *CONTROL_SENDER.lock(),
            ) {
                if let Err(e) = sender.send(&packet) {
                    info!("Server disconnected. Cause: {e:?}");
                    set_hud_message(SERVER_DISCONNECTED_MESSAGE);

                    break;
                }
            }

            if Instant::now() > keepalive_deadline {
                if let Some(sender) = &mut *CONTROL_SENDER.lock() {
                    sender.send(&ClientControlPacket::KeepAlive).ok();

                    keepalive_deadline = Instant::now() + KEEPALIVE_INTERVAL;
                }
            }

            #[cfg(target_os = "android")]
            if Instant::now() > battery_deadline {
                let (gauge_value, is_plugged) = battery_manager.status();
                if let Some(sender) = &mut *CONTROL_SENDER.lock() {
                    sender
                        .send(&ClientControlPacket::Battery(crate::BatteryPacket {
                            device_id: *alvr_common::HEAD_ID,
                            gauge_value,
                            is_plugged,
                        }))
                        .ok();
                }

                battery_deadline = Instant::now() + Duration::from_secs(5);
            }
        }

        if let Some(notifier) = &*DISCONNECT_SERVER_NOTIFIER.lock() {
            notifier.send(()).ok();
        }
    });

    let control_receive_thread = thread::spawn(move || {
        let mut disconnection_deadline = Instant::now() + KEEPALIVE_TIMEOUT;
        while IS_STREAMING.value() {
            let maybe_packet = control_receiver.recv(STREAMING_RECV_TIMEOUT);

            match maybe_packet {
                Ok(ServerControlPacket::InitializeDecoder(config)) => {
                    decoder::create_decoder(config);
                }
                Ok(ServerControlPacket::Restarting) => {
                    info!("{SERVER_RESTART_MESSAGE}");
                    set_hud_message(SERVER_RESTART_MESSAGE);
                    if let Some(notifier) = &*DISCONNECT_SERVER_NOTIFIER.lock() {
                        notifier.send(()).ok();
                    }

                    return;
                }
                Ok(_) => (),
                Err(ConnectionError::TryAgain(_)) => {
                    if Instant::now() > disconnection_deadline {
                        info!("{CONNECTION_TIMEOUT_MESSAGE}");
                        set_hud_message(CONNECTION_TIMEOUT_MESSAGE);
                        if let Some(notifier) = &*DISCONNECT_SERVER_NOTIFIER.lock() {
                            notifier.send(()).ok();
                        }

                        return;
                    } else {
                        continue;
                    }
                }
                Err(e) => {
                    info!("{SERVER_DISCONNECTED_MESSAGE} Cause: {e}");
                    set_hud_message(SERVER_DISCONNECTED_MESSAGE);
                    if let Some(notifier) = &*DISCONNECT_SERVER_NOTIFIER.lock() {
                        notifier.send(()).ok();
                    }

                    return;
                }
            }

            disconnection_deadline = Instant::now() + KEEPALIVE_TIMEOUT;
        }
    });

    let stream_receive_thread = thread::spawn(move || {
        while IS_STREAMING.value() {
            let res = stream_socket.recv();
            match res {
                Ok(()) => (),
                Err(ConnectionError::TryAgain(_)) => continue,
                Err(e) => {
                    info!("Client disconnected. Cause: {e}");
                    set_hud_message(SERVER_DISCONNECTED_MESSAGE);
                    if let Some(notifier) = &*DISCONNECT_SERVER_NOTIFIER.lock() {
                        notifier.send(()).ok();
                    }

                    return;
                }
            }
        }
    });

    // Block here
    disconnect_receiver.recv().ok();

    IS_STREAMING.set(false);
    *CONTROL_SENDER.lock() = None;
    *LOG_CHANNEL_SENDER.lock() = None;
    *TRACKING_SENDER.lock() = None;
    *STATISTICS_SENDER.lock() = None;

    EVENT_QUEUE
        .lock()
        .push_back(ClientCoreEvent::StreamingStopped);

    #[cfg(target_os = "android")]
    {
        *crate::decoder::DECODER_SINK.lock() = None;
        *crate::decoder::DECODER_SOURCE.lock() = None;
    }

    video_receive_thread.join().ok();
    game_audio_thread.join().ok();
    microphone_thread.join().ok();
    haptics_receive_thread.join().ok();
    control_send_thread.join().ok();
    control_receive_thread.join().ok();
    stream_receive_thread.join().ok();

    Ok(())
}
