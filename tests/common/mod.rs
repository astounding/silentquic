// SPDX-License-Identifier: 0BSD

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

pub fn test_ip() -> IpAddr {
    std::env::var("QUIETQUIC_TEST_ADDR")
        .unwrap_or_else(|_| "127.0.0.1".into())
        .parse()
        .expect("QUIETQUIC_TEST_ADDR must be an IP address")
}

pub fn bind_addr() -> SocketAddr {
    SocketAddr::new(test_ip(), next_configured_port().unwrap_or(0))
}

pub fn bind_addr_string() -> String {
    bind_addr().to_string()
}

pub fn addr_with_port_string(port: u16) -> String {
    SocketAddr::new(test_ip(), port).to_string()
}

pub fn sender_bind_addr() -> SocketAddr {
    SocketAddr::new(test_ip(), 0)
}

pub fn reserve_port() -> u16 {
    if let Some(port) = next_configured_port() {
        return port;
    }
    let socket = UdpSocket::bind(bind_addr()).expect("reserve UDP port");
    socket.local_addr().expect("reserved UDP addr").port()
}

fn next_configured_port() -> Option<u16> {
    let base: u16 = std::env::var("QUIETQUIC_TEST_PORT_BASE")
        .ok()?
        .parse()
        .expect("QUIETQUIC_TEST_PORT_BASE must be a u16 port");
    let offset = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    base.checked_add(offset)
        .or_else(|| panic!("QUIETQUIC_TEST_PORT_BASE plus test offset overflowed u16"))
}
