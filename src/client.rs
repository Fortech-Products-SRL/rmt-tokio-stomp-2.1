use bytes::{Buf, BufMut, BytesMut};
use futures::prelude::*;
use futures::sink::SinkExt;
use socket2::{SockRef, TcpKeepalive};
use std::net::ToSocketAddrs;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
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

/// The interval at which this client promises to send STOMP heartbeats.
///
/// Pass this (or a fraction of it for extra safety margin) to
/// [`heartbeat_task`] as the `interval` argument.
pub const HEARTBEAT_SEND_INTERVAL: Duration = Duration::from_millis(HEARTBEAT_CX as u64);

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
/// If successful, returns the framed transport.
///
/// # Heartbeats
/// The STOMP handshake negotiates that the client will send a heartbeat every
/// [`HEARTBEAT_SEND_INTERVAL`] (10 s). Brokers with an inactivity monitor
/// (ActiveMQ, RabbitMQ, …) will forcibly close the connection if nothing is
/// received within that window. Spawn a [`heartbeat_task`] alongside your
/// receive loop to fulfil this obligation:
/// ```no_run
/// # async fn example() -> anyhow::Result<()> {
/// use futures::prelude::*;
/// use tokio_stomp_2_1::client;
/// let conn = client::connect("127.0.0.1:61613", None, None).await?;
/// let (sink, stream) = conn.split();
/// tokio::spawn(client::heartbeat_task(sink, client::HEARTBEAT_SEND_INTERVAL));
/// // drive `stream` on the current task …
/// # Ok(()) }
/// ```
pub async fn connect(
    address: &str,
    login: Option<String>,
    passcode: Option<String>,
) -> Result<ClientTransport> {
    let addr = address
        .to_socket_addrs()
        .map_err(|e| anyhow!("DNS resolution failed for '{}': {}", address, e))?
        .next()
        .ok_or_else(|| anyhow!("address '{}' resolved to no socket addresses", address))?;
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
    let addr = address
        .to_socket_addrs()
        .map_err(|e| anyhow!("DNS resolution failed for '{}': {}", address, e))?
        .next()
        .ok_or_else(|| anyhow!("address '{}' resolved to no socket addresses", address))?;
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
    client_handshake(&mut transport, address, login, passcode).await?;
    Ok(transport)
}

/// Perform the STOMP CONNECT handshake over any framed transport.
async fn client_handshake<T>(
    transport: &mut Framed<T, ClientCodec>,
    host: &str,
    login: Option<String>,
    passcode: Option<String>,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let connect = Message {
        content: ToServer::Connect {
            accept_version: "1.2".into(),
            host: host.to_string(),
            login,
            passcode,
            heartbeat: Some((HEARTBEAT_CX, HEARTBEAT_CY)),
        },
        extra_headers: vec![],
    };
    // Send the CONNECT frame
    transport.send(connect).await?;
    // Receive CONNECTED reply
    let msg = transport.next().await.transpose()?;
    if let Some(FromServer::Connected {
        version, heartbeat, ..
    }) = msg.as_ref().map(|m| &m.content)
    {
        log::info!(
            "STOMP CONNECTED: version={}, broker heartbeat={:?}, client offered=heart-beat:{},{}",
            version,
            heartbeat,
            HEARTBEAT_CX,
            HEARTBEAT_CY
        );
        Ok(())
    } else {
        Err(anyhow!("unexpected reply: {:?}", msg))
    }
}

/// Sends a STOMP heartbeat (bare `\n`) to `sink` at the given `interval`
/// until the sink errors or is dropped. Exits silently on any send error.
///
/// The STOMP handshake negotiates that the client will send a heartbeat every
/// [`HEARTBEAT_SEND_INTERVAL`] (10 s). Brokers with an inactivity monitor
/// (ActiveMQ, RabbitMQ, …) will forcibly close the connection if no traffic is
/// received within that window. Spawn this task alongside your receive loop
/// to fulfil the obligation:
///
/// ```no_run
/// # async fn example() -> anyhow::Result<()> {
/// use futures::prelude::*;
/// use tokio_stomp_2_1::client;
/// let conn = client::connect("127.0.0.1:61613", None, None).await?;
/// let (sink, stream) = conn.split();
/// tokio::spawn(client::heartbeat_task(sink, client::HEARTBEAT_SEND_INTERVAL));
/// // drive `stream` on the current task …
/// # Ok(()) }
/// ```
pub async fn heartbeat_task<S>(mut sink: S, interval: Duration)
where
    S: SinkExt<Message<ToServer>> + Unpin,
{
    let mut ticker = tokio::time::interval(interval);
    // Skip missed ticks: avoid sending a burst of heartbeats after a stall.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if sink.send(ToServer::Heartbeat.into()).await.is_err() {
            // Sink closed or underlying connection dropped; exit silently.
            break;
        }
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
        let mut had_heartbeat = false;
        loop {
            if src.starts_with(b"\r\n") {
                src.advance(2);
                had_heartbeat = true;
            } else if src.starts_with(b"\n") {
                src.advance(1);
                had_heartbeat = true;
            } else {
                break;
            }
        }
        if src.is_empty() {
            if had_heartbeat {
                // Surface heartbeat arrival so the application layer can
                // track connection liveness and implement receive timeouts.
                return Ok(Some(Message {
                    content: FromServer::Heartbeat,
                    extra_headers: vec![],
                }));
            }
            return Ok(None);
        }

        // Parse the frame. The nom error type holds a &[u8] that borrows `src`,
        // so we convert it to an owned String before touching `src` again.
        let parse_result = match frame::parse_frame(src) {
            Ok((remain, frame)) => Ok((
                Message::<FromServer>::from_frame(frame),
                remain.as_ptr() as usize - src.as_ptr() as usize,
            )),
            Err(nom::Err::Incomplete(_)) => return Ok(None),
            // Convert error to String to release the immutable borrow on `src`.
            Err(e) => Err(format!("Parse failed: {:?}", e)),
        };

        let (item, offset) = match parse_result {
            Ok(v) => v,
            Err(msg) => {
                // Skip past the next frame terminator (\x00) so subsequent
                // decode calls can attempt to parse the next frame rather than
                // looping forever on the same malformed bytes.
                let skip = src
                    .iter()
                    .position(|&b| b == b'\x00')
                    .map(|pos| pos + 1) // consume the \x00 itself
                    .unwrap_or(src.len()); // no terminator found: drain entire buffer
                src.advance(skip);
                bail!("{}", msg);
            }
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
