use std::{collections::HashMap, env, time::Duration};
use ipnetwork::IpNetwork;
use tauri::{AppHandle, Emitter};
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, time::timeout};
use futures::future::join_all;

use once_cell::sync::Lazy;
use super::probe::probe::{load_probes_from_nmap, Probe};

static PROBES: Lazy<HashMap<u16, Vec<Probe>>> = Lazy::new(|| {
    let mut path = env::current_dir().expect("Failed to get current directory");
    path.push("src/core/probe/nmap-service-probes.txt");
    let probes = load_probes_from_nmap(path).unwrap();
    probes
});

#[derive(serde::Deserialize, Clone)]
pub struct ScanParams {
    alive_scan: bool,
    port_scan: bool,
    ports: Vec<u16>,
    finger_scan: bool,
    timeout: Option<u64>,
}

async fn finger_scan(stream: &mut TcpStream, tmout: Duration) -> Option<String> {
    let mut buffer = [0u8; 1024];

    let banner_result = timeout(tmout, stream.peek(&mut buffer)).await;
    let (banner_size, mut banner_str) = match banner_result {
        Ok(Ok(size)) => {
            let s = String::from_utf8_lossy(&buffer[..size]).to_string();
            (size, s)
        }
        _ => return None,
    };

    let port = stream.local_addr().ok()?.port();
    if let Some(probes) = PROBES.get(&port) {
        for probe in probes {
            if probe.pattern.is_match(&banner_str) {
                return Some(String::from_utf8_lossy(&probe.payload).to_string());
            }
        }
    }

    if let Ok(_) = timeout(tmout, stream.write_all(b"\r\n")).await {
        if let Ok(Ok(new_size)) = timeout(tmout, stream.read(&mut buffer)).await {
            if new_size > banner_size {
                let new_data = String::from_utf8_lossy(&buffer[banner_size..new_size]);
                banner_str.push_str(&new_data);
            }
        }
    }

    if let Some(probes) = PROBES.get(&port) {
        for probe in probes {
            if probe.pattern.is_match(&banner_str) {
                return Some(String::from_utf8_lossy(&probe.payload).to_string());
            }
        }
    }

    Some(banner_str)
}