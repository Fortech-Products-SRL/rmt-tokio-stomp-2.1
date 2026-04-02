use bytes::{Buf, BufMut, BytesMut};
use futures::prelude::*;
use futures::sink::SinkExt;
use socket2::{SockRef, TcpKeepalive};
use std::net::ToSocketAddrs;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder, Framed};

use native_tls::TlsConnector as NativeTlsConnector;
use tokio_native_tls::{TlsConnector, TlsStream};

pub type ClientTransport = Framed<TcpStream, ClientCodec>;
pub type ClientTlsTransport = Framed<TlsStream<TcpStream>, ClientCodec>;

use crate::frame;
use crate::{FromServer, Message, Result, ToServer};
use anyhow::{anyhow, bail};

// Heartbeat: client sends one every 10 s, wants to receive one every 30 s.
// This tells the broker to send a bare \n every ~30 s, and we promise to
// send one every ~10 s, which keeps NAT sessions and broker InactivityMonitors
// satisfied in both directions.
const HEARTBEAT_CX: u32 = 10_000;
const HEARTBEAT_CY: u32 = 30_000;

/// Configure OS-level TCP keepalive on a connected `TcpStream`.
///
/// After 30 s of idle the OS starts sending keepalive probes every 10 s.
/// This ensures that a half-open (silently dead) socket is detected and
/// returns an error from `poll_read`, unblocking `conn.next()`.
fn apply_tcp_keepalive(tcp: &TcpStream) -> Result<()> {
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    SockRef::from(tcp).set_tcp_keepalive(&keepalive)?;
    Ok(())
}

/// Connect to a STOMP server via TCP, including the connection handshake.
/// If successful, returns a tuple of a message stream and a sender,
/// which may be used to receive and send messages respectively.
pub async fn connect(
    address: &str,
    login: Option<String>,
    passcode: Option<String>,
) -> Result<ClientTransport> {
    let addr = address.to_socket_addrs().unwrap().next().unwrap();
    let tcp = TcpStream::connect(&addr).await?;
    apply_tcp_keepalive(&tcp)?;
    let mut transport = ClientCodec.framed(tcp);
    client_handshake(&mut transport, address, login, passcode).await?;
    Ok(transport)
}

pub async fn connect_tls(
    domain: &str,
    address: &str,
    login: Option<String>,
    passcode: Option<String>,
) -> Result<ClientTlsTransport> {
    let addr = address.to_socket_addrs()?.next().unwrap();
    // Set up the TLS connector
    let native_tls_connector = NativeTlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let tls_connector = TlsConnector::from(native_tls_connector);
    let tcp_stream = TcpStream::connect(&addr).await?;
    // Apply keepalive before the TLS handshake wraps the stream.
    apply_tcp_keepalive(&tcp_stream)?;
    // Perform the TLS handshake
    let tls_stream: TlsStream<TcpStream> = tls_connector.connect(domain, tcp_stream).await?;
    let mut transport = ClientCodec.framed(tls_stream);
    client_handshake_tls(&mut transport, address, login, passcode).await?;
    Ok(transport)
}

async fn client_handshake(
    transport: &mut ClientTransport,
    address: &str,
    login: Option<String>,
    passcode: Option<String>,
) -> Result<()> {
    let connect = Message {
        content: ToServer::Connect {
            accept_version: "1.2".into(),
            host: address.to_string(),
            login,
            passcode,
            heartbeat: None,
        },
        extra_headers: vec![],
    };
    // Send the message
    transport.send(connect).await?;
    // Receive reply
    let msg = transport.next().await.transpose()?;
    if let Some(FromServer::Connected { .. }) = msg.as_ref().map(|m| &m.content) {
        Ok(())
    } else {
        Err(anyhow!("unexpected reply: {:?}", msg))
    }
}

async fn client_handshake_tls(
    transport: &mut ClientTlsTransport,
    address: &str,
    login: Option<String>,
    passcode: Option<String>,
) -> Result<()> {
    let connect = Message {
        content: ToServer::Connect {
            accept_version: "1.2".into(),
            host: address.to_string(),
            login,
            passcode,
            heartbeat: Some((HEARTBEAT_CX, HEARTBEAT_CY)),
        },
        extra_headers: vec![],
    };
    // Send the message
    transport.send(connect).await?;
    // Receive reply
    let msg = transport.next().await.transpose()?;
    if let Some(FromServer::Connected { .. }) = msg.as_ref().map(|m| &m.content) {
        Ok(())
    } else {
        Err(anyhow!("unexpected reply: {:?}", msg))
    }
}

/// Convenience function to build a Subscribe message
pub fn subscribe(dest: impl Into<String>, id: impl Into<String>) -> Message<ToServer> {
    ToServer::Subscribe {
        destination: dest.into(),
        id: id.into(),
        ack: None,
    }
    .into()
}

pub struct ClientCodec;

impl Decoder for ClientCodec {
    type Item = Message<FromServer>;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // STOMP 1.2 §2.10: the broker sends bare \n (or \r\n) bytes as
        // heartframes.  Strip them before attempting to parse a full frame so
        // they do not confuse the nom parser.
        loop {
            if src.starts_with(b"\r\n") {
                src.advance(2);
            } else if src.starts_with(b"\n") {
                src.advance(1);
            } else {
                break;
            }
        }
        if src.is_empty() {
            return Ok(None);
        }

        let (item, offset) = match frame::parse_frame(src) {
            Ok((remain, frame)) => (
                Message::<FromServer>::from_frame(frame),
                remain.as_ptr() as usize - src.as_ptr() as usize,
            ),
            Err(nom::Err::Incomplete(_)) => return Ok(None),
            Err(e) => bail!("Parse failed: {:?}", e),
        };
        src.advance(offset);
        item.map(Some)
    }
}

impl Encoder<Message<ToServer>> for ClientCodec {
    type Error = anyhow::Error;

    fn encode(
        &mut self,
        item: Message<ToServer>,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        // Heartbeat is a bare EOL, not a real STOMP frame.
        if matches!(&item.content, ToServer::Heartbeat) {
            dst.put_u8(b'\n');
            return Ok(());
        }
        item.to_frame().serialize(dst);
        Ok(())
    }
}
