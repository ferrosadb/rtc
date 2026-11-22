//! A data channel opened right after another closed must survive the old channel's stream reset.
//!
//! RFC 8831 §6.7 closes a data channel by resetting its outgoing SCTP stream (RFC 6525); the
//! peer answers by resetting its own outgoing stream with the same id. RFC 8832 §6 then lets an
//! endpoint reuse a stream identifier only "for which the corresponding incoming and outgoing
//! streams are unused" — i.e. once both resets have completed.
//!
//! The defect this pins: closing a channel freed its stream id at once, before either reset had
//! completed. The next channel created took that lowest free id, and when the late reset for the
//! old channel completed, SCTP reported the id closed again and the *new* channel was torn down.
//! Closing one channel and opening another straight away lost the second.
//!
//! Both peers run a real DTLS + SCTP association over loopback UDP and are driven through the
//! public API only.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Ceiling for any single wait. Reached only on failure.
const WAIT: Duration = Duration::from_secs(8);

/// How long the new channel is watched after it opens. On loopback the old channel's reset
/// round trip completes in a few milliseconds; this is generous by two orders of magnitude.
const SETTLE: Duration = Duration::from_millis(1000);

/// Everything one peer has observed, by channel handle.
#[derive(Default)]
struct Seen {
    opened: Vec<RTCDataChannelId>,
    closed: Vec<RTCDataChannelId>,
    messages: Vec<(RTCDataChannelId, Vec<u8>)>,
}

struct Peer {
    pc: RTCPeerConnection,
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    seen: Seen,
}

impl Peer {
    async fn new() -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let local_addr = socket.local_addr()?;
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(Instant::now())?;
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: local_addr.ip().to_string(),
                port: local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;
        Ok(Self {
            pc,
            socket,
            local_addr,
            seen: Seen::default(),
        })
    }

    async fn flush(&mut self) -> Result<()> {
        while let Some(msg) = self.pc.poll_write() {
            self.socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
        while let Some(event) = self.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(event) = event {
                match event {
                    RTCDataChannelEvent::OnOpen(id) => self.seen.opened.push(id),
                    RTCDataChannelEvent::OnClose(id) => self.seen.closed.push(id),
                    _ => {}
                }
            }
        }
        while let Some(msg) = self.pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, m) = msg.message {
                self.seen.messages.push((id, m.data.to_vec()));
            }
        }
        Ok(())
    }

    fn deliver(&mut self, buf: &[u8], peer_addr: SocketAddr) {
        let result = self.pc.handle_read(TaggedBytesMut {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: self.local_addr,
                peer_addr,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(buf),
        });
        if let Err(err) = result {
            log::warn!("handle_read failed: {err}");
        }
    }

    fn label_of(&mut self, id: RTCDataChannelId) -> Option<String> {
        self.pc.data_channel(id).map(|dc| dc.label().to_owned())
    }
}

struct Pair {
    offer: Peer,
    answer: Peer,
}

impl Pair {
    async fn connect() -> Result<Self> {
        let mut offer = Peer::new().await?;
        let mut answer = Peer::new().await?;
        // Without a channel the offer carries no application section and no SCTP association.
        let bootstrap = offer.pc.create_data_channel("bootstrap", None)?.id();

        let sdp = offer.pc.create_offer(None)?;
        offer
            .pc
            .set_local_description(Instant::now(), sdp.clone())?;
        answer.pc.set_remote_description(Instant::now(), sdp)?;
        let sdp = answer.pc.create_answer(None)?;
        answer
            .pc
            .set_local_description(Instant::now(), sdp.clone())?;
        offer.pc.set_remote_description(Instant::now(), sdp)?;

        let mut pair = Self { offer, answer };
        pair.pump_until("the bootstrap channel opens on both sides", |p| {
            p.offer.seen.opened.contains(&bootstrap) && !p.answer.seen.opened.is_empty()
        })
        .await?;
        Ok(pair)
    }

    /// One turn of the event loop: flush both peers, then wait for a datagram or a timer.
    async fn turn(&mut self, buf_a: &mut [u8], buf_b: &mut [u8]) -> Result<()> {
        self.offer.flush().await?;
        self.answer.flush().await?;

        let far = Instant::now() + Duration::from_secs(30);
        let next = self
            .offer
            .pc
            .poll_timeout()
            .unwrap_or(far)
            .min(self.answer.pc.poll_timeout().unwrap_or(far));
        let delay = next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));

        let (offer_socket, answer_socket) = (
            Arc::clone(&self.offer.socket),
            Arc::clone(&self.answer.socket),
        );
        tokio::select! {
            _ = tokio::time::sleep(delay) => {
                let now = Instant::now();
                self.offer.pc.handle_timeout(now).ok();
                self.answer.pc.handle_timeout(now).ok();
            }
            Ok((n, from)) = offer_socket.recv_from(buf_a) => self.offer.deliver(&buf_a[..n], from),
            Ok((n, from)) = answer_socket.recv_from(buf_b) => self.answer.deliver(&buf_b[..n], from),
        }
        Ok(())
    }

    async fn pump_until(&mut self, what: &str, done: impl Fn(&Pair) -> bool) -> Result<()> {
        let (mut buf_a, mut buf_b) = (vec![0u8; 2000], vec![0u8; 2000]);
        let start = Instant::now();
        while start.elapsed() < WAIT {
            self.turn(&mut buf_a, &mut buf_b).await?;
            self.offer.flush().await?;
            self.answer.flush().await?;
            if done(self) {
                return Ok(());
            }
        }
        bail!("timed out waiting for: {what}")
    }

    async fn pump_for(&mut self, period: Duration) -> Result<()> {
        let (mut buf_a, mut buf_b) = (vec![0u8; 2000], vec![0u8; 2000]);
        let start = Instant::now();
        while start.elapsed() < period {
            self.turn(&mut buf_a, &mut buf_b).await?;
        }
        self.offer.flush().await?;
        self.answer.flush().await
    }

    /// The handle the answerer gave the channel the offerer labelled `label`.
    fn answer_handle(&mut self, label: &str) -> Option<RTCDataChannelId> {
        let opened = self.answer.seen.opened.clone();
        opened
            .into_iter()
            .find(|id| self.answer.label_of(*id).as_deref() == Some(label))
    }
}

/// The offerer closes a channel, waits for the answerer to see it close, and opens the next one
/// at once. The next channel must open on both sides, stay open past the old channel's reset,
/// and carry messages both before and after it.
#[tokio::test]
async fn a_channel_opened_right_after_another_closed_survives() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let mut pair = Pair::connect().await?;

    let first = pair.offer.pc.create_data_channel("first", None)?.id();
    pair.pump_until("the first channel opens on both sides", |p| {
        p.offer.seen.opened.contains(&first) && p.answer.seen.opened.len() >= 2
    })
    .await?;
    let first_remote = pair.answer_handle("first").expect("answerer saw `first`");
    let first_stream = pair.offer.pc.data_channel(first).unwrap().stream_id();

    pair.offer.pc.data_channel(first).unwrap().close()?;
    pair.pump_until("the answerer sees the first channel close", |p| {
        p.answer.seen.closed.contains(&first_remote)
    })
    .await?;

    let second = pair.offer.pc.create_data_channel("second", None)?.id();
    pair.pump_until("the second channel opens on both sides", |p| {
        p.offer.seen.opened.contains(&second) && p.answer.seen.opened.len() >= 3
    })
    .await?;
    let second_remote = pair.answer_handle("second").expect("answerer saw `second`");
    let second_stream = pair.offer.pc.data_channel(second).unwrap().stream_id();

    pair.offer
        .pc
        .data_channel(second)
        .unwrap()
        .send_text(Instant::now(), "before the reset settles")?;
    pair.pump_for(SETTLE).await?;

    assert!(
        !pair.offer.seen.closed.contains(&second),
        "the offerer closed the second channel (stream {second_stream:?}) although nobody asked \
         it to; the first channel was on stream {first_stream:?}"
    );
    assert!(
        !pair.answer.seen.closed.contains(&second_remote),
        "the answerer closed the second channel (stream {second_stream:?}); the first channel \
         was on stream {first_stream:?}"
    );

    pair.offer
        .pc
        .data_channel(second)
        .ok_or_else(|| anyhow::anyhow!("the offerer no longer has the second channel"))?
        .send_text(Instant::now(), "after the reset settles")?;
    pair.pump_until("the answerer receives both messages", |p| {
        p.answer
            .seen
            .messages
            .iter()
            .filter(|(id, _)| *id == second_remote)
            .count()
            >= 2
    })
    .await?;

    let got: Vec<&[u8]> = pair
        .answer
        .seen
        .messages
        .iter()
        .filter(|(id, _)| *id == second_remote)
        .map(|(_, m)| m.as_slice())
        .collect();
    assert_eq!(
        got,
        vec![
            b"before the reset settles".as_slice(),
            b"after the reset settles".as_slice()
        ]
    );

    // Holding the id is only half the contract: once the reset has completed it must be
    // released, or every close would leak a stream id. The lowest free id is the first
    // channel's again.
    let third = pair.offer.pc.create_data_channel("third", None)?.id();
    pair.pump_until("the third channel opens on both sides", |p| {
        p.offer.seen.opened.contains(&third) && p.answer.seen.opened.len() >= 4
    })
    .await?;
    let third_stream = pair.offer.pc.data_channel(third).unwrap().stream_id();
    assert_eq!(
        first_stream, third_stream,
        "the first channel's stream id was never released after its reset completed \
         (second channel is on {second_stream:?})"
    );
    assert_ne!(first_stream, second_stream);

    pair.offer.pc.close().ok();
    pair.answer.pc.close().ok();
    Ok(())
}
