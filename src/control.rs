use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;

use crate::state::{ManagedIpset, STATE};

pub const CONTROL_SOCKET_PATH: &str = "/run/dockerwall.sock";

pub fn run_control_server(dns_port: u16) -> Result<(), Box<dyn Error + Send + Sync>> {
    if Path::new(CONTROL_SOCKET_PATH).exists() {
        fs::remove_file(CONTROL_SOCKET_PATH)?;
    }

    let listener = UnixListener::bind(CONTROL_SOCKET_PATH)?;
    fs::set_permissions(CONTROL_SOCKET_PATH, fs::Permissions::from_mode(0o600))?;
    println!("dockerwall control socket listening on {CONTROL_SOCKET_PATH}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(err) = handle_control_connection(stream, dns_port) {
                        eprintln!("control error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

fn handle_control_connection(mut stream: UnixStream, dns_port: u16) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut stream);
        reader.read_line(&mut line)?;
    }

    let command = line.trim_end_matches('\n');

    if command == "STATS" {
        let report = crate::stats::get_stats_report();
        stream.write_all(report.as_bytes())?;
        return Ok(());
    }

    if command == "INFO" {
        stream.write_all(format!("OK\t{dns_port}\n").as_bytes())?;
        return Ok(());
    }

    if let Some(rest) = command.strip_prefix("CREATE\t") {
        let mut parts = rest.splitn(3, '\t');
        let name = parts.next().ok_or("missing ipset name")?.trim();
        let subnet = parts.next().ok_or("missing subnet")?.trim();
        let raw_domains = parts.next().ok_or("missing domains")?;

        if name.is_empty() {
            stream.write_all(b"ERR\tmissing ipset name\n")?;
            return Ok(());
        }

        if !subnet.is_empty() {
            crate::stats::register_network(name.to_owned(), subnet.to_owned());
        }

        let allowed_domain_patterns: Vec<String> = raw_domains
            .split(',')
            .map(str::trim)
            .filter(|domain| !domain.is_empty())
            .map(ToOwned::to_owned)
            .collect();

        let mut state = STATE.blocking_write();
        state.insert(
            name.to_owned(),
            ManagedIpset {
                allowed_domain_patterns,
                ips: Default::default(),
            },
        );

        stream.write_all(b"OK\tcreated\n")?;
        return Ok(());
    }

    if let Some(name) = command.strip_prefix("REMOVE\t") {
        let name = name.trim();
        if name.is_empty() {
            stream.write_all(b"ERR\tmissing ipset name\n")?;
            return Ok(());
        }

        let mut state = STATE.blocking_write();
        state.remove(name);
        stream.write_all(b"OK\tremoved\n")?;
        return Ok(());
    }

    stream.write_all(b"ERR\tunknown command\n")?;
    Ok(())
}

pub fn send_control_command(payload: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stream = UnixStream::connect(CONTROL_SOCKET_PATH)?;
    stream.write_all(payload.as_bytes())?;

    let mut response = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response)?;

    if response.starts_with("OK\t") {
        return Ok(());
    }

    if let Some(message) = response.trim_end().strip_prefix("ERR\t") {
        return Err(message.to_owned().into());
    }

    Err("invalid daemon response".into())
}

pub fn get_dns_port() -> Result<u16, Box<dyn Error + Send + Sync>> {
    let mut stream = UnixStream::connect(CONTROL_SOCKET_PATH)?;
    stream.write_all(b"INFO\n")?;

    let mut response = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response)?;

    if let Some(rest) = response.strip_prefix("OK\t") {
        let port: u16 = rest.trim_end().parse()?;
        return Ok(port);
    }

    if let Some(message) = response.trim_end().strip_prefix("ERR\t") {
        return Err(message.to_owned().into());
    }

    Err("invalid daemon response".into())
}
