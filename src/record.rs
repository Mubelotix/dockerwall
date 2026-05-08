use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

const CONTROL_SOCKET_PATH: &str = "/run/dockerwall.sock";

pub fn stream_records() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stream = UnixStream::connect(CONTROL_SOCKET_PATH)?;
    stream.write_all(b"RECORD\n")?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    if response.trim_end() != "OK" {
        return Err(format!("daemon rejected record stream: {}", response.trim()).into());
    }

    println!("listening for unmatched domains...");
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break; // connection closed
        }
        print!("{line}");
    }

    Ok(())
}
