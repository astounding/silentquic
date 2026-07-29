// SPDX-License-Identifier: 0BSD
//! Minimal bounded full-duplex stream pattern.
//!
//! A real application obtains `(send, recv)` from `Connection::open_bi` or
//! `accept_bi`, then moves each half into independently polled work.

use quietquic::conn::{ConnError, RecvStream, SendStream};

#[allow(dead_code)]
async fn exchange(mut send: SendStream, mut recv: RecvStream) -> Result<Vec<u8>, ConnError> {
    let receive = async move {
        let mut response = Vec::new();
        loop {
            let chunk = recv.read(16 * 1024).await?;
            if chunk.is_empty() {
                return Ok::<_, ConnError>(response);
            }
            response.extend_from_slice(&chunk);
            if response.len() > 1024 * 1024 {
                return Err(ConnError::ReadLimitExceeded { limit: 1024 * 1024 });
            }
        }
    };

    let send_request = async move {
        send.write_all(b"request").await?;
        send.finish().await
    };

    let (response, ()) = tokio::try_join!(receive, send_request)?;
    Ok(response)
}

fn main() {
    println!("See the source of this example for the bounded full-duplex pattern.");
}
