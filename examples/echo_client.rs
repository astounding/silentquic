// SPDX-License-Identifier: 0BSD
//! A minimal cloaked echo client, for manual and cross-host testing.
//!
//! Connects, opens one bidirectional stream, sends a message, half-closes, and
//! reads the echo back.
//!
//! ```text
//! cargo run --example echo_client -- <server_addr> <psk_hex> <message> [client_id]
//! cargo run --example echo_client -- 127.0.0.1:29411 $(printf '00%.0s' {1..32}) hello
//! ```
//!
//! `psk_hex` is 64 hex characters (32 bytes) and must match the server's.
//!
//! The local source port is ephemeral by default (what ordinary QUIC clients
//! do). To pin a source address and/or port — for an egress firewall that
//! allowlists one, or to force traffic out a specific interface on a multi-homed
//! host — add a `bind` line to the client config, e.g. `bind = "0.0.0.0:29411"`
//! or `bind = "192.168.64.5:0"` to pin only the interface. See
//! `ClientConfigFile::bind`.

use quietquic::client::Client;
use quietquic::config::ClientConfigFile;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let server = args
        .next()
        .ok_or("usage: echo_client <server_addr> <psk_hex> [message] [client_id] [bind_addr]")?;
    let psk = args.next().ok_or("missing <psk_hex> (64 hex chars)")?;
    let message = args
        .next()
        .unwrap_or_else(|| "hello from quietquic".to_string());
    let client_id = args.next().unwrap_or_else(|| "peer".to_string());
    // Optional: pin the local source address/port. Omitted ⇒ ephemeral on any
    // interface, which is the default and the right choice unless a firewall or
    // a multi-homed host demands otherwise.
    let bind = args.next();

    let bind_line = match &bind {
        Some(b) => format!("bind = \"{b}\"\n"),
        None => String::new(),
    };
    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id = \"{client_id}\"\npsk = \"{psk}\"\nserver = \"{server}\"\n{bind_line}"
    ))?;
    if let Some(b) = &bind {
        println!("pinning local source address to {b}");
    }

    println!("dialing {server} ...");
    let started = std::time::Instant::now();
    let conn = Client::connect(cfg).await?;
    println!(
        "handshake complete with {} in {:?}",
        conn.remote_address(),
        started.elapsed()
    );

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(message.as_bytes()).await?;
    send.finish().await?;
    println!("sent {} bytes", message.len());

    let echo = recv.read_to_end(1024 * 1024).await?;
    println!("echo: {:?}", String::from_utf8_lossy(&echo));

    if echo == message.as_bytes() {
        println!("OK — round trip matched");
    } else {
        return Err("echo did not match what was sent".into());
    }

    conn.close(0, b"").await?;
    Ok(())
}
