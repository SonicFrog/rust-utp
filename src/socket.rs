use std::cmp::{max, min};
use std::collections::VecDeque;
use std::future::Future;
use std::io::{ErrorKind, Result};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::error::SocketError;
use crate::packet::*;
use crate::time::*;
use crate::util::*;

use rand;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{
    unbounded_channel, UnboundedReceiver, UnboundedSender,
};
use tokio::sync::Mutex;
use tokio::time::{
    delay_for, timeout, Delay as TokioDelay, Instant as TokioInstant,
};

use tracing::debug;

// For simplicity's sake, let us assume no packet will ever exceed the
// Ethernet maximum transfer unit of 1500 bytes.
const BUF_SIZE: usize = 1500;
const GAIN: f64 = 1.0;
const ALLOWED_INCREASE: u32 = 1;
const TARGET: f64 = 100_000.0; // 100 milliseconds
const MSS: u32 = 1400;
const MIN_CWND: u32 = 2;
const INIT_CWND: u32 = 2;
const INITIAL_CONGESTION_TIMEOUT: u64 = 1000; // one second
const MIN_CONGESTION_TIMEOUT: u64 = 500; // 500 ms
const MAX_CONGESTION_TIMEOUT: u64 = 60_000; // one minute
const BASE_HISTORY: usize = 10; // base delays history size
const MAX_SYN_RETRIES: u32 = 5; // maximum connection retries
const MAX_RETRANSMISSION_RETRIES: u32 = 5; // maximum retransmission retries
const WINDOW_SIZE: u32 = 1024 * 1024; // local receive window size

/// Maximum age of base delay sample (60 seconds)
const MAX_BASE_DELAY_AGE: Delay = Delay(60_000_000);

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
enum SocketState {
    New,
    Connected,
    SynSent,
    FinSent,
    ResetReceived,
    Closed,
}

struct DelayDifferenceSample {
    received_at: Timestamp,
    difference: Delay,
}

/// A structure that represents a uTP (Micro Transport Protocol) connection
/// between a local socket and a remote socket.
///
/// The socket will be closed when the value is dropped (either explicitly or
/// when it goes out of scope).
///
/// The default maximum retransmission retries is 5, which translates to about
/// 16 seconds. It can be changed by assigning the desired maximum
/// retransmission retries to a socket's `max_retransmission_retries` field.
/// Notice that the initial congestion timeout is 500 ms and doubles with each
/// timeout.
struct UtpSocket {
    /// The wrapped UDP socket
    socket: UdpSocket,

    /// Remote peer
    connected_to: SocketAddr,

    /// Sender connection identifier
    sender_connection_id: u16,

    /// Receiver connection identifier
    receiver_connection_id: u16,

    /// Sequence number for the next packet
    seq_nr: u16,

    /// Sequence number of the latest acknowledged packet sent by the remote peer
    ack_nr: u16,

    /// Socket state
    state: SocketState,

    /// Received but not acknowledged packets
    incoming_buffer: Vec<Packet>,

    /// Sent but not yet acknowledged packets
    send_window: Vec<Packet>,

    /// Packets not yet sent
    unsent_queue: VecDeque<Packet>,

    /// How many ACKs did the socket receive for packet with sequence number
    /// equal to `ack_nr`
    duplicate_ack_count: u32,

    /// Sequence number of the latest packet the remote peer acknowledged
    last_acked: u16,

    /// Timestamp of the latest packet the remote peer acknowledged
    last_acked_timestamp: Timestamp,

    /// Sequence number of the last packet removed from the incoming buffer
    last_dropped: u16,

    /// Round-trip time to remote peer
    rtt: i32,

    /// Variance of the round-trip time to the remote peer
    rtt_variance: i32,

    /// Data from the latest packet not yet returned in `recv_from`
    pending_data: Vec<u8>,

    /// Bytes in flight
    curr_window: u32,

    /// Window size of the remote peer
    remote_wnd_size: u32,

    /// Rolling window of packet delay to remote peer
    base_delays: VecDeque<Delay>,

    /// Rolling window of the difference between sending a packet and receiving
    /// its acknowledgement
    current_delays: Vec<DelayDifferenceSample>,

    /// Difference between timestamp of the latest packet received and time of
    /// reception
    their_delay: Delay,

    /// Start of the current minute for sampling purposes
    last_rollover: Timestamp,

    /// Current congestion timeout in milliseconds
    congestion_timeout: u64,

    /// Congestion window in bytes
    cwnd: u32,

    /// Maximum retransmission retries
    pub max_retransmission_retries: u32,
}

impl UtpSocket {
    /// Creates a new UTP socket from the given UDP socket and the remote peer's
    /// address.
    ///
    /// The connection identifier of the resulting socket is randomly generated.
    fn from_raw_parts(s: UdpSocket, src: SocketAddr) -> UtpSocket {
        let (receiver_id, sender_id) = generate_sequential_identifiers();

        UtpSocket {
            socket: s,
            connected_to: src,
            receiver_connection_id: receiver_id,
            sender_connection_id: sender_id,
            seq_nr: 1,
            ack_nr: 0,
            state: SocketState::New,
            incoming_buffer: Vec::new(),
            send_window: Vec::new(),
            unsent_queue: VecDeque::new(),
            duplicate_ack_count: 0,
            last_acked: 0,
            last_acked_timestamp: Timestamp::default(),
            last_dropped: 0,
            rtt: 0,
            rtt_variance: 0,
            pending_data: Vec::new(),
            curr_window: 0,
            remote_wnd_size: 0,
            current_delays: Vec::new(),
            base_delays: VecDeque::with_capacity(BASE_HISTORY),
            their_delay: Delay::default(),
            last_rollover: Timestamp::default(),
            congestion_timeout: INITIAL_CONGESTION_TIMEOUT,
            cwnd: INIT_CWND * MSS,
            max_retransmission_retries: MAX_RETRANSMISSION_RETRIES,
        }
    }

    /// Creates a new UTP socket from the given address.
    pub async fn bind(addr: SocketAddr) -> Result<UtpSocket> {
        let socket = UdpSocket::bind(addr).await?;

        Ok(UtpSocket::from_raw_parts(socket, addr))
    }

    /// Returns the socket address that this socket was created from.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns the socket address of the remote peer of this UTP connection.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        if self.state == SocketState::Connected
            || self.state == SocketState::FinSent
        {
            Ok(self.connected_to)
        } else {
            Err(SocketError::NotConnected.into())
        }
    }

    /// Opens a connection to a remote host by hostname or IP address.
    pub async fn connect(addr: SocketAddr) -> Result<UtpSocket> {
        let my_addr = match addr {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0u16).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0u16).into(),
        };
        let mut socket = UtpSocket::bind(my_addr).await?;
        socket.connected_to = addr;

        let mut packet = Packet::new();
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(socket.receiver_connection_id);
        packet.set_seq_nr(socket.seq_nr);

        let mut len = 0;
        let mut buf = [0; BUF_SIZE];

        let mut syn_timeout = socket.congestion_timeout;
        for _ in 0..MAX_SYN_RETRIES {
            packet.set_timestamp(now_microseconds());

            // Send packet
            debug!("connecting to {}", socket.connected_to);
            socket
                .socket
                .send_to(packet.as_ref(), socket.connected_to)
                .await?;
            socket.state = SocketState::SynSent;
            debug!("sent {:?}", packet);

            // Validate response
            let to = Duration::from_millis(syn_timeout);

            match timeout(to, socket.socket.recv_from(&mut buf)).await {
                Ok(Ok((read, src))) => {
                    socket.connected_to = src;
                    len = read;
                    break;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    debug!("timed out, retrying");
                    syn_timeout *= 2;
                    continue;
                }
            };
        }

        let addr = socket.connected_to;
        let packet = Packet::try_from(&buf[..len])?;
        debug!("received {:?}", packet);
        socket.handle_packet(&packet, addr)?;

        debug!("connected to: {}", socket.connected_to);

        Ok(socket)
    }

    /// Gracefully closes connection to peer.
    ///
    /// This method allows both peers to receive all packets still in
    /// flight.
    pub async fn close(&mut self) -> Result<()> {
        // Nothing to do if the socket's already closed or not connected
        if self.state == SocketState::Closed
            || self.state == SocketState::New
            || self.state == SocketState::SynSent
        {
            return Ok(());
        }

        let local = self.socket.local_addr()?;

        debug!("closing {} -> {}", local, self.connected_to);

        // Flush unsent and unacknowledged packets
        self.flush().await?;

        debug!("close flush completed");

        let mut packet = Packet::new();
        packet.set_connection_id(self.sender_connection_id);
        packet.set_seq_nr(self.seq_nr);
        packet.set_ack_nr(self.ack_nr);
        packet.set_timestamp(now_microseconds());
        packet.set_type(PacketType::Fin);

        // Send FIN
        self.socket
            .send_to(packet.as_ref(), self.connected_to)
            .await?;
        debug!("sent {:?}", packet);
        self.state = SocketState::FinSent;

        // Receive JAKE
        let mut buf = [0; BUF_SIZE];
        while self.state != SocketState::Closed {
            self.recv(&mut buf).await?;
        }

        debug!("closed {} -> {}", local, self.connected_to);

        Ok(())
    }

    /// Receives data from socket.
    ///
    /// On success, returns the number of bytes read and the sender's address.
    /// Returns 0 bytes read after receiving a FIN packet when the remaining
    /// in-flight packets are consumed.
    pub async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr)> {
        let read = self.flush_incoming_buffer(buf);

        if read > 0 {
            Ok((read, self.connected_to))
        } else {
            // If the socket received a reset packet and all data has been
            // flushed, then it can't receive anything else
            if self.state == SocketState::ResetReceived {
                return Err(SocketError::ConnectionReset.into());
            }

            loop {
                // A closed socket with no pending data can only "read" 0 new
                // bytes.
                if self.state == SocketState::Closed {
                    return Ok((0, self.connected_to));
                }

                match self.recv(buf).await {
                    Ok((0, _src)) => continue,
                    Ok(x) => return Ok(x),
                    Err(e) => return Err(e),
                }
            }
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut b = [0; BUF_SIZE + HEADER_SIZE];
        let start = Instant::now();
        let read;
        let src;
        let mut retries = 0;

        // Try to receive a packet and handle timeouts
        loop {
            // Abort loop if the current try exceeds the maximum number of
            // retransmission retries.
            if retries >= self.max_retransmission_retries {
                self.state = SocketState::Closed;
                return Err(SocketError::ConnectionTimedOut.into());
            }

            if self.state != SocketState::New {
                let to = Duration::from_millis(self.congestion_timeout);
                debug!(
                    "setting read timeout of {} ms",
                    self.congestion_timeout
                );

                match timeout(to, self.socket.recv_from(&mut b)).await {
                    Ok(Ok((r, s))) => {
                        read = r;
                        src = s;
                        break;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        debug!("recv_from timed out");
                        self.handle_receive_timeout().await?;
                    }
                };
            } else {
                match self.socket.recv_from(&mut b).await {
                    Ok((r, s)) => {
                        read = r;
                        src = s;
                        break;
                    }
                    Err(e) => return Err(e),
                }
            };

            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_secs() * 1000
                + (elapsed.subsec_millis() / 1_000_000) as u64;
            debug!("{} ms elapsed", elapsed_ms);
            retries += 1;
        }

        // Decode received data into a packet
        let packet = match Packet::try_from(&b[..read]) {
            Ok(packet) => packet,
            Err(e) => {
                debug!("{}", e);
                debug!("Ignoring invalid packet");
                return Ok((0, self.connected_to));
            }
        };
        debug!("received {:?}", packet);

        // Process packet, including sending a reply if necessary
        if let Some(mut pkt) = self.handle_packet(&packet, src)? {
            pkt.set_wnd_size(WINDOW_SIZE);
            self.socket.send_to(pkt.as_ref(), src).await?;
            debug!("sent {:?}", pkt);
        }

        // Insert data packet into the incoming buffer if it isn't a duplicate
        // of a previously discarded packet
        if packet.get_type() == PacketType::Data
            && packet.seq_nr().wrapping_sub(self.last_dropped) > 0
        {
            self.insert_into_buffer(packet);
        }

        // Flush incoming buffer if possible
        let read = self.flush_incoming_buffer(buf);

        Ok((read, src))
    }

    async fn handle_receive_timeout(&mut self) -> Result<()> {
        self.congestion_timeout *= 2;
        self.cwnd = MSS;

        // There are three possible cases here:
        //
        // - If the socket is sending and waiting for acknowledgements (the send
        //   window is not empty), resend the first unacknowledged packet;
        //
        // - If the socket is not sending and it hasn't sent a FIN yet, then
        //   it's waiting for incoming packets: send a fast resend request;
        //
        // - If the socket sent a FIN previously, resend it.
        debug!(
            "self.send_window: {:?}",
            self.send_window
                .iter()
                .map(Packet::seq_nr)
                .collect::<Vec<u16>>()
        );

        if self.send_window.is_empty() {
            // The socket is trying to close, all sent packets were acknowledged,
            // and it has already sent a FIN: resend it.
            if self.state == SocketState::FinSent {
                let mut packet = Packet::new();
                packet.set_connection_id(self.sender_connection_id);
                packet.set_seq_nr(self.seq_nr);
                packet.set_ack_nr(self.ack_nr);
                packet.set_timestamp(now_microseconds());
                packet.set_type(PacketType::Fin);

                // Send FIN
                self.socket
                    .send_to(packet.as_ref(), self.connected_to)
                    .await?;
                debug!("resent FIN: {:?}", packet);
            } else if self.state != SocketState::New {
                // The socket is waiting for incoming packets but the remote
                // peer is silent: send a fast resend request.
                debug!("sending fast resend request");
                self.send_fast_resend_request();
            }
        } else {
            // The socket is sending data packets but there is no reply from the
            // remote peer: resend the first unacknowledged packet with the
            // current timestamp.
            let packet = &mut self.send_window[0];
            packet.set_timestamp(now_microseconds());
            self.socket
                .send_to(packet.as_ref(), self.connected_to)
                .await?;
            debug!("resent {:?}", packet);
        }

        Ok(())
    }

    fn prepare_reply(&self, original: &Packet, t: PacketType) -> Packet {
        let mut resp = Packet::new();
        resp.set_type(t);
        let self_t_micro = now_microseconds();
        let other_t_micro = original.timestamp();
        let time_difference: Delay = abs_diff(self_t_micro, other_t_micro);
        resp.set_timestamp(self_t_micro);
        resp.set_timestamp_difference(time_difference);
        resp.set_connection_id(self.sender_connection_id);
        resp.set_seq_nr(self.seq_nr);
        resp.set_ack_nr(self.ack_nr);

        resp
    }

    /// Removes a packet in the incoming buffer and updates the current
    /// acknowledgement number.
    fn advance_incoming_buffer(&mut self) -> Option<Packet> {
        if !self.incoming_buffer.is_empty() {
            let packet = self.incoming_buffer.remove(0);
            debug!("Removed packet from incoming buffer: {:?}", packet);
            self.ack_nr = packet.seq_nr();
            self.last_dropped = self.ack_nr;
            Some(packet)
        } else {
            None
        }
    }

    /// Discards sequential, ordered packets in incoming buffer, starting from
    /// the most recently acknowledged to the most recent, as long as there are
    /// no missing packets. The discarded packets' payload is written to the
    /// slice `buf`, starting in position `start`.
    /// Returns the last written index.
    fn flush_incoming_buffer(&mut self, buf: &mut [u8]) -> usize {
        fn unsafe_copy(src: &[u8], dst: &mut [u8]) -> usize {
            let max_len = min(src.len(), dst.len());
            unsafe {
                use std::ptr::copy;
                copy(src.as_ptr(), dst.as_mut_ptr(), max_len);
            }
            max_len
        }

        // Return pending data from a partially read packet
        if !self.pending_data.is_empty() {
            let flushed = unsafe_copy(&self.pending_data[..], buf);

            if flushed == self.pending_data.len() {
                self.pending_data.clear();
                self.advance_incoming_buffer();
            } else {
                self.pending_data = self.pending_data[flushed..].to_vec();
            }

            return flushed;
        }

        // only flush data that we acked (e.g. the packets are in order in the buffer)
        if !self.incoming_buffer.is_empty()
            && (self.ack_nr.wrapping_sub(self.incoming_buffer[0].seq_nr()) >= 1)
        {
            let flushed =
                unsafe_copy(&self.incoming_buffer[0].payload()[..], buf);

            if flushed == self.incoming_buffer[0].payload().len() {
                self.advance_incoming_buffer();
            } else {
                self.pending_data =
                    self.incoming_buffer[0].payload()[flushed..].to_vec();
            }

            return flushed;
        } else if !self.incoming_buffer.is_empty() {
            debug!(
                "not flushing out of order data, acked={} > cached={}",
                self.ack_nr,
                self.incoming_buffer[0].seq_nr()
            );
        }

        0
    }

    /// Sends data on the socket to the remote peer. On success, returns the
    /// number of bytes written.
    //
    // # Implementation details
    //
    // This method inserts packets into the send buffer and keeps trying to
    // advance the send window until an ACK corresponding to the last packet is
    // received.
    //
    // Note that the buffer passed to `send_to` might exceed the maximum packet
    // size, which will result in the data being split over several packets.
    pub async fn send_to(&mut self, buf: &[u8]) -> Result<usize> {
        if self.state == SocketState::Closed {
            return Err(SocketError::ConnectionClosed.into());
        }

        let total_length = buf.len();

        for chunk in buf.chunks(MSS as usize - HEADER_SIZE) {
            let mut packet = Packet::with_payload(chunk);
            packet.set_seq_nr(self.seq_nr);
            packet.set_ack_nr(self.ack_nr);
            packet.set_connection_id(self.sender_connection_id);

            self.unsent_queue.push_back(packet);

            // Intentionally wrap around sequence number
            self.seq_nr = self.seq_nr.wrapping_add(1);
        }

        // Send every packet in the queue
        self.send().await?;

        Ok(total_length)
    }

    /// Consumes acknowledgements for every pending packet.
    pub async fn flush(&mut self) -> Result<()> {
        let mut buf = [0u8; BUF_SIZE];
        while !self.send_window.is_empty() {
            debug!("packets in send window: {}", self.send_window.len());
            self.recv(&mut buf).await?;
        }

        Ok(())
    }

    /// Sends every packet in the unsent packet queue.
    async fn send(&mut self) -> Result<()> {
        while let Some(mut packet) = self.unsent_queue.pop_front() {
            self.send_packet(&mut packet).await?;
            self.curr_window += packet.len() as u32;
            self.send_window.push(packet);
        }
        Ok(())
    }

    fn max_inflight(&self) -> u32 {
        let max_inflight = min(self.cwnd, self.remote_wnd_size);
        max(MIN_CWND * MSS, max_inflight)
    }

    /// Send one packet.
    #[inline]
    async fn send_packet(&mut self, packet: &mut Packet) -> Result<()> {
        debug!("current window: {}", self.send_window.len());

        packet.set_timestamp(now_microseconds());
        packet.set_timestamp_difference(self.their_delay);

        self.socket
            .send_to(packet.as_ref(), self.connected_to)
            .await?;

        debug!("sent {:?}", packet);

        Ok(())
    }

    // Insert a new sample in the base delay list.
    //
    // The base delay list contains at most `BASE_HISTORY` samples, each sample
    // is the minimum measured over a period of a minute (MAX_BASE_DELAY_AGE).
    fn update_base_delay(&mut self, base_delay: Delay, now: Timestamp) {
        if self.base_delays.is_empty()
            || now - self.last_rollover > MAX_BASE_DELAY_AGE
        {
            // Update last rollover
            self.last_rollover = now;

            // Drop the oldest sample, if need be
            if self.base_delays.len() == BASE_HISTORY {
                self.base_delays.pop_front();
            }

            // Insert new sample
            self.base_delays.push_back(base_delay);
        } else {
            // Replace sample for the current minute if the delay is lower
            let last_idx = self.base_delays.len() - 1;
            if base_delay < self.base_delays[last_idx] {
                self.base_delays[last_idx] = base_delay;
            }
        }
    }

    /// Inserts a new sample in the current delay list after removing samples
    /// older than one RTT, as specified in RFC6817.
    fn update_current_delay(&mut self, v: Delay, now: Timestamp) {
        // Remove samples more than one RTT old
        let rtt = (self.rtt as i64 * 100).into();
        while !self.current_delays.is_empty()
            && now - self.current_delays[0].received_at > rtt
        {
            self.current_delays.remove(0);
        }

        // Insert new measurement
        self.current_delays.push(DelayDifferenceSample {
            received_at: now,
            difference: v,
        });
    }

    fn update_congestion_timeout(&mut self, current_delay: i32) {
        let delta = self.rtt - current_delay;
        self.rtt_variance += (delta.abs() - self.rtt_variance) / 4;
        self.rtt += (current_delay - self.rtt) / 8;
        self.congestion_timeout = max(
            (self.rtt + self.rtt_variance * 4) as u64,
            MIN_CONGESTION_TIMEOUT,
        );
        self.congestion_timeout =
            min(self.congestion_timeout, MAX_CONGESTION_TIMEOUT);

        debug!("current_delay: {}", current_delay);
        debug!("delta: {}", delta);
        debug!("self.rtt_variance: {}", self.rtt_variance);
        debug!("self.rtt: {}", self.rtt);
        debug!("self.congestion_timeout: {}", self.congestion_timeout);
    }

    /// Calculates the filtered current delay in the current window.
    ///
    /// The current delay is calculated through application of the exponential
    /// weighted moving average filter with smoothing factor 0.333 over the
    /// current delays in the current window.
    fn filtered_current_delay(&self) -> Delay {
        let input = self.current_delays.iter().map(|delay| &delay.difference);
        (ewma(input, 0.333) as i64).into()
    }

    /// Calculates the lowest base delay in the current window.
    fn min_base_delay(&self) -> Delay {
        self.base_delays.iter().min().cloned().unwrap_or_default()
    }

    /// Builds the selective acknowledgement extension data for usage in packets.
    fn build_selective_ack(&self) -> Vec<u8> {
        let stashed = self
            .incoming_buffer
            .iter()
            .filter(|pkt| pkt.seq_nr() > self.ack_nr + 1)
            .map(|pkt| (pkt.seq_nr() - self.ack_nr - 2) as usize)
            .map(|diff| (diff / 8, diff % 8));

        let mut sack = Vec::new();
        for (byte, bit) in stashed {
            // Make sure the amount of elements in the SACK vector is a
            // multiple of 4 and enough to represent the lost packets
            while byte >= sack.len() || sack.len() % 4 != 0 {
                sack.push(0u8);
            }

            sack[byte] |= 1 << bit;
        }

        sack
    }

    /// Sends a fast resend request to the remote peer.
    ///
    /// A fast resend request consists of sending three State packets
    /// (acknowledging the last received packet) in quick succession.
    fn send_fast_resend_request(&mut self) {
        for _ in 0..3usize {
            let mut packet = Packet::new();
            packet.set_type(PacketType::State);
            let self_t_micro = now_microseconds();
            packet.set_timestamp(self_t_micro);
            packet.set_timestamp_difference(self.their_delay);
            packet.set_connection_id(self.sender_connection_id);
            packet.set_seq_nr(self.seq_nr);
            packet.set_ack_nr(self.ack_nr);
            self.unsent_queue.push_back(packet);
        }
    }

    fn resend_lost_packet(&mut self, lost_packet_nr: u16) {
        debug!("---> resend_lost_packet({}) <---", lost_packet_nr);
        match self
            .send_window
            .iter()
            .position(|pkt| pkt.seq_nr() == lost_packet_nr)
        {
            None => debug!("Packet {} not found", lost_packet_nr),
            Some(position) => {
                debug!("self.send_window.len(): {}", self.send_window.len());
                debug!("position: {}", position);
                let packet = self.send_window[position].clone();

                self.unsent_queue.push_back(packet);

                // We intentionally don't increase `curr_window` because
                // otherwise a packet's length would be counted more than once
            }
        }
        debug!("---> END resend_lost_packet <---");
    }

    /// Forgets sent packets that were acknowledged by the remote peer.
    fn advance_send_window(&mut self) {
        // The reason I'm not removing the first element in a loop while its
        // sequence number is smaller than `last_acked` is because of wrapping
        // sequence numbers, which would create the sequence [..., 65534, 65535,
        // 0, 1, ...]. If `last_acked` is smaller than the first packet's
        // sequence number because of wraparound (for instance, 1), no packets
        // would be removed, as the condition `seq_nr < last_acked` would fail
        // immediately.
        //
        // On the other hand, I can't keep removing the first packet in a loop
        // until its sequence number matches `last_acked` because it might never
        // match, and in that case no packets should be removed.
        if let Some(position) = self
            .send_window
            .iter()
            .position(|packet| packet.seq_nr() == self.last_acked)
        {
            for _ in 0..=position {
                let packet = self.send_window.remove(0);
                debug!("removing {} bytes from send window", packet.len());
                debug!(
                    "{} packets left in send window",
                    self.send_window.len()
                );
                self.curr_window -= packet.len() as u32;
            }
        }
        debug!("self.curr_window: {}", self.curr_window);
    }

    /// Handles an incoming packet, updating socket state accordingly.
    ///
    /// Returns the appropriate reply packet, if needed.
    fn handle_packet(
        &mut self,
        packet: &Packet,
        src: SocketAddr,
    ) -> Result<Option<Packet>> {
        debug!("({:?}, {:?})", self.state, packet.get_type());

        // Acknowledge only if the packet strictly follows the previous one
        if packet.seq_nr().wrapping_sub(self.ack_nr) == 1 {
            self.ack_nr = packet.seq_nr();
        }

        // Reset connection if connection id doesn't match and this isn't a SYN
        if packet.get_type() != PacketType::Syn
            && self.state != SocketState::SynSent
            && !(packet.connection_id() == self.sender_connection_id
                || packet.connection_id() == self.receiver_connection_id)
        {
            return Ok(Some(self.prepare_reply(packet, PacketType::Reset)));
        }

        // Update remote window size
        self.remote_wnd_size = packet.wnd_size();
        debug!("self.remote_wnd_size: {}", self.remote_wnd_size);

        // Update remote peer's delay between them sending the packet and us
        // receiving it
        let now = now_microseconds();
        self.their_delay = abs_diff(now, packet.timestamp());
        debug!("self.their_delay: {}", self.their_delay);

        match (self.state, packet.get_type()) {
            (SocketState::New, PacketType::Syn) => {
                self.connected_to = src;
                self.ack_nr = packet.seq_nr();
                self.seq_nr = rand::random();
                self.receiver_connection_id = packet.connection_id() + 1;
                self.sender_connection_id = packet.connection_id();
                self.state = SocketState::Connected;
                self.last_dropped = self.ack_nr;

                Ok(Some(self.prepare_reply(packet, PacketType::State)))
            }
            (_, PacketType::Syn) => {
                Ok(Some(self.prepare_reply(packet, PacketType::Reset)))
            }
            (SocketState::SynSent, PacketType::State) => {
                self.connected_to = src;
                self.ack_nr = packet.seq_nr();
                self.seq_nr += 1;
                self.state = SocketState::Connected;
                self.last_acked = packet.ack_nr();
                self.last_acked_timestamp = now_microseconds();
                Ok(None)
            }
            (SocketState::SynSent, _) => Err(SocketError::InvalidReply.into()),
            (SocketState::Connected, PacketType::Data)
            | (SocketState::FinSent, PacketType::Data) => {
                Ok(self.handle_data_packet(packet))
            }
            (SocketState::Connected, PacketType::State) => {
                self.handle_state_packet(packet);
                Ok(None)
            }
            (SocketState::Connected, PacketType::Fin)
            | (SocketState::FinSent, PacketType::Fin) => {
                if packet.ack_nr() < self.seq_nr {
                    debug!("FIN received but there are missing acknowledgements for sent packets");
                }
                let mut reply = self.prepare_reply(packet, PacketType::State);
                if packet.seq_nr().wrapping_sub(self.ack_nr) > 1 {
                    debug!(
                            "current ack_nr ({}) is behind received packet seq_nr ({})",
                            self.ack_nr,
                            packet.seq_nr()
                        );

                    // Set SACK extension payload if the packet is not in order
                    let sack = self.build_selective_ack();

                    if !sack.is_empty() {
                        reply.set_sack(sack);
                    }
                }

                debug!("received FIN from {}, connection is closed", src);

                // Give up, the remote peer might not care about our missing packets
                self.state = SocketState::Closed;
                Ok(Some(reply))
            }
            (SocketState::Closed, PacketType::Fin) => {
                Ok(Some(self.prepare_reply(packet, PacketType::State)))
            }
            (SocketState::FinSent, PacketType::State) => {
                if packet.ack_nr() == self.seq_nr {
                    debug!("connection closed succesfully");
                    self.state = SocketState::Closed;
                } else {
                    self.handle_state_packet(packet);
                }
                Ok(None)
            }
            (_, PacketType::Reset) => {
                self.state = SocketState::ResetReceived;
                Err(SocketError::ConnectionReset.into())
            }
            (state, ty) => {
                let message = format!(
                    "Unimplemented handling for ({:?},{:?})",
                    state, ty
                );
                debug!("{}", message);
                Err(SocketError::Other(message).into())
            }
        }
    }

    fn handle_data_packet(&mut self, packet: &Packet) -> Option<Packet> {
        // If a FIN was previously sent, reply with a FIN packet acknowledging
        // the received packet.
        let packet_type = if self.state == SocketState::FinSent {
            PacketType::Fin
        } else {
            PacketType::State
        };
        let mut reply = self.prepare_reply(packet, packet_type);

        if packet.seq_nr().wrapping_sub(self.ack_nr) > 1 {
            debug!(
                "current ack_nr ({}) is behind received packet seq_nr ({})",
                self.ack_nr,
                packet.seq_nr()
            );

            // Set SACK extension payload if the packet is not in order
            let sack = self.build_selective_ack();

            if !sack.is_empty() {
                reply.set_sack(sack);
            }
        }

        Some(reply)
    }

    fn queuing_delay(&self) -> Delay {
        let filtered_current_delay = self.filtered_current_delay();
        let min_base_delay = self.min_base_delay();
        let queuing_delay = filtered_current_delay - min_base_delay;

        debug!("filtered_current_delay: {}", filtered_current_delay);
        debug!("min_base_delay: {}", min_base_delay);
        debug!("queuing_delay: {}", queuing_delay);

        queuing_delay
    }

    /// Calculates the new congestion window size, increasing it or decreasing it.
    ///
    /// This is the core of uTP, the [LEDBAT][ledbat_rfc] congestion algorithm.
    /// It depends on estimating the queuing delay between the two peers, and
    /// adjusting the congestion window accordingly.
    ///
    /// `off_target` is a normalized value representing the difference between
    /// the current queuing delay and a fixed target delay (`TARGET`).
    /// `off_target` ranges between -1.0 and 1.0. A positive value makes the
    /// congestion window increase, while a negative value makes the congestion
    /// window decrease.
    ///
    /// `bytes_newly_acked` is the number of bytes acknowledged by an inbound
    /// `State` packet. It may be the size of the packet explicitly acknowledged
    /// by the inbound packet (i.e., with sequence number equal to the inbound
    /// packet's acknowledgement number), or every packet implicitly
    /// acknowledged (every packet with sequence number between the previous
    /// inbound `State` packet's acknowledgement number and the current inbound
    /// `State` packet's acknowledgement number).
    ///
    ///[ledbat_rfc]: https://tools.ietf.org/html/rfc6817
    fn update_congestion_window(
        &mut self,
        off_target: f64,
        bytes_newly_acked: u32,
    ) {
        let flightsize = self.curr_window;

        let cwnd_increase =
            GAIN * off_target * bytes_newly_acked as f64 * MSS as f64;
        let cwnd_increase = cwnd_increase / self.cwnd as f64;
        debug!("cwnd_increase: {}", cwnd_increase);

        self.cwnd = (self.cwnd as f64 + cwnd_increase) as u32;
        let max_allowed_cwnd = flightsize + ALLOWED_INCREASE * MSS;
        self.cwnd = min(self.cwnd, max_allowed_cwnd);
        self.cwnd = max(self.cwnd, MIN_CWND * MSS);

        debug!("cwnd: {}", self.cwnd);
        debug!("max_allowed_cwnd: {}", max_allowed_cwnd);
    }

    fn handle_state_packet(&mut self, packet: &Packet) {
        if packet.ack_nr() == self.last_acked {
            self.duplicate_ack_count += 1;
        } else {
            self.last_acked = packet.ack_nr();
            self.last_acked_timestamp = now_microseconds();
            self.duplicate_ack_count = 1;
        }

        // Update congestion window size
        if let Some(index) = self
            .send_window
            .iter()
            .position(|p| packet.ack_nr() == p.seq_nr())
        {
            // Calculate the sum of the size of every packet implicitly and
            // explicitly acknowledged by the inbound packet (i.e., every packet
            // whose sequence number precedes the inbound packet's
            // acknowledgement number, plus the packet whose sequence number
            // matches)
            let bytes_newly_acked = self
                .send_window
                .iter()
                .take(index + 1)
                .fold(0, |acc, p| acc + p.len());

            // Update base and current delay
            let now = now_microseconds();
            let our_delay = now - self.send_window[index].timestamp();
            debug!("our_delay: {}", our_delay);
            self.update_base_delay(our_delay, now);
            self.update_current_delay(our_delay, now);

            let off_target: f64 =
                (TARGET - u32::from(self.queuing_delay()) as f64) / TARGET;
            debug!("off_target: {}", off_target);

            self.update_congestion_window(off_target, bytes_newly_acked as u32);

            // Update congestion timeout in milliseconds
            let rtt = u32::from(our_delay - self.queuing_delay()) / 1000;
            self.update_congestion_timeout(rtt as i32);
        }

        let mut packet_loss_detected: bool =
            !self.send_window.is_empty() && self.duplicate_ack_count == 3;

        // Process extensions, if any
        for extension in packet.extensions() {
            if extension.get_type() == ExtensionType::SelectiveAck {
                // If three or more packets are acknowledged past the implicit missing one,
                // assume it was lost.
                if extension.iter().count_ones() >= 3 {
                    self.resend_lost_packet(packet.ack_nr() + 1);
                    packet_loss_detected = true;
                }

                if let Some(last_seq_nr) =
                    self.send_window.last().map(Packet::seq_nr)
                {
                    let lost_packets = extension
                        .iter()
                        .enumerate()
                        .filter(|&(_, received)| !received)
                        .map(|(idx, _)| packet.ack_nr() + 2 + idx as u16)
                        .take_while(|&seq_nr| seq_nr < last_seq_nr);

                    for seq_nr in lost_packets {
                        debug!("SACK: packet {} lost", seq_nr);
                        self.resend_lost_packet(seq_nr);
                        packet_loss_detected = true;
                    }
                }
            } else {
                debug!(
                    "Unknown extension {:?}, ignoring",
                    extension.get_type()
                );
            }
        }

        // Three duplicate ACKs mean a fast resend request. Resend the first
        // unacknowledged packet if the incoming packet doesn't have a SACK
        // extension. If it does, the lost packets were already resent.
        if !self.send_window.is_empty()
            && self.duplicate_ack_count == 3
            && !packet
                .extensions()
                .any(|ext| ext.get_type() == ExtensionType::SelectiveAck)
        {
            self.resend_lost_packet(packet.ack_nr() + 1);
        }

        // Packet lost, halve the congestion window
        if packet_loss_detected {
            debug!("packet loss detected, halving congestion window");
            self.cwnd = max(self.cwnd / 2, MIN_CWND * MSS);
            debug!("cwnd: {}", self.cwnd);
        }

        // Success, advance send window
        self.advance_send_window();
    }

    /// Inserts a packet into the socket's buffer.
    ///
    /// The packet is inserted in such a way that the packets in the buffer are
    /// sorted according to their sequence number in ascending order. This
    /// allows storing packets that were received out of order.
    ///
    /// Trying to insert a duplicate of a packet will silently fail.
    /// it's more recent (larger timestamp).
    fn insert_into_buffer(&mut self, packet: Packet) {
        // Immediately push to the end if the packet's sequence number comes
        // after the last packet's.
        if self
            .incoming_buffer
            .last()
            .map_or(false, |p| packet.seq_nr() > p.seq_nr())
        {
            self.incoming_buffer.push(packet);
        } else {
            // Find index following the most recent packet before the one we
            // wish to insert
            let i = self
                .incoming_buffer
                .iter()
                .filter(|p| p.seq_nr() < packet.seq_nr())
                .count();

            if self
                .incoming_buffer
                .get(i)
                .map_or(true, |p| p.seq_nr() != packet.seq_nr())
            {
                self.incoming_buffer.insert(i, packet);
            }
        }
    }
}

/// Polls a `Future` and returns from current function unless the future is
/// `Ready`
macro_rules! ready_unpin {
    ($data:expr, $cx:expr) => {
        match unsafe { Pin::new_unchecked(&mut $data) }.poll($cx) {
            Poll::Ready(v) => v,
            Poll::Pending => return Poll::Pending,
        }
    };
}

/// Polls a `Future` that returns a `Result` and returns from the current
/// function unless the feature is `Ready` and the `Result` is `Ok`
macro_rules! ready_try_unpin {
    ($data:expr, $cx:expr) => {
        match ready_unpin!($data, $cx) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        }
    };
}

/// Polls a `Future` while ensuring pinning
macro_rules! poll_unpin {
    ($data:expr, $cx:expr) => {{
        #[allow()]
        let x = unsafe { Pin::new_unchecked(&mut $data) }.poll($cx);
        x
    }};
}

macro_rules! ready_try {
    ($data:expr) => {{
        match ($data) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(v)) => v,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
    }};
}

/// A reference to an existing `UtpSocket` that can be shared amongst multiple
/// tasks. This can't function unless the corresponding `UtpSocketDriver` is
/// scheduled to run on the same runtime.
pub struct UtpSocketRef(Arc<Mutex<UtpSocket>>, SocketAddr);

impl UtpSocketRef {
    fn new(socket: Arc<Mutex<UtpSocket>>, local: SocketAddr) -> Self {
        Self(socket, local)
    }

    /// Bind an unconnected `UtpSocket` on the given address.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let udp = UdpSocket::bind(addr).await?;
        let resolved = udp.local_addr()?;
        let socket = UtpSocket::from_raw_parts(udp, resolved);
        let lock = Arc::new(Mutex::new(socket));

        debug!("bound utp socket on {}", resolved);

        Ok(Self::new(lock, resolved))
    }

    /// Connect to a remote host using this `UtpSocket`
    pub async fn connect(
        self,
        dst: SocketAddr,
    ) -> Result<(UtpStream, UtpStreamDriver)> {
        let mut socket = self.0.lock().await;

        socket.connected_to = dst;

        let mut packet = Packet::new();
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(socket.receiver_connection_id);
        packet.set_seq_nr(socket.seq_nr);

        let mut len = 0;
        let mut buf = [0; BUF_SIZE];

        let mut syn_timeout = socket.congestion_timeout;
        for _ in 0..MAX_SYN_RETRIES {
            packet.set_timestamp(now_microseconds());

            debug!("connecting to {}", socket.connected_to);
            let dst = socket.connected_to;

            socket.socket.send_to(packet.as_ref(), dst).await?;
            socket.state = SocketState::SynSent;
            debug!("sent {:?}", packet);

            let to = Duration::from_millis(syn_timeout);

            match timeout(to, socket.socket.recv_from(&mut buf)).await {
                Ok(Ok((read, src))) => {
                    socket.connected_to = src;
                    len = read;
                    break;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    debug!("timed out, retrying");
                    syn_timeout *= 2;
                    continue;
                }
            };
        }

        let remote = socket.connected_to;
        let packet = Packet::try_from(&buf[..len])?;
        debug!("received {:?}", packet);
        socket.handle_packet(&packet, remote)?;

        debug!("connected to: {}", socket.connected_to);

        let (tx, rx) = unbounded_channel();

        let local = socket.local_addr()?;

        mem::drop(socket);

        let driver = UtpStreamDriver::new(self.0.clone(), tx);
        let stream = UtpStream::new(self.0, rx, local, remote);

        Ok((stream, driver))
    }

    /// Accept an incoming connection using this `UtpSocket`. This also
    /// returns a `UtpStreamDriver` that must be scheduled on a runtime
    /// in order for the associated `UtpStream` to work properly.
    /// Accepting a new connection will consume this listener.
    pub async fn accept(self) -> Result<(UtpStream, UtpStreamDriver)> {
        let (src, dst);

        loop {
            let mut socket = self.0.lock().await;
            let mut buf = [0u8; BUF_SIZE];

            let (read, remote) = socket.socket.recv_from(&mut buf).await?;

            let packet = Packet::try_from(&buf[..read])?;

            debug!("accept receive {:?}", packet);

            if let Ok(Some(reply)) = socket.handle_packet(&packet, remote) {
                src = socket.socket.local_addr()?;
                dst = socket.connected_to;

                socket.socket.send_to(reply.as_ref(), dst).await?;

                debug!("sent {:?} to {}", reply, dst);
                debug!("accepted connection {} -> {}", dst, src);
                break;
            }
        }

        let (tx, rx) = unbounded_channel();
        let socket = self.0;
        let stream = UtpStream::new(socket.clone(), rx, src, dst);
        let driver = UtpStreamDriver::new(socket, tx);

        Ok((stream, driver))
    }

    /// Get the local address for this `UtpSocket`
    pub fn local_addr(&self) -> SocketAddr {
        self.1
    }
}

/// A `UtpStream` that can be used to read and write in a more convenient
/// fashion with the `AsyncRead` and `AsyncWrite` traits.
pub struct UtpStream {
    socket: Arc<Mutex<UtpSocket>>,
    receiver: UnboundedReceiver<Result<()>>,
    local: SocketAddr,
    remote: SocketAddr,
}

impl UtpStream {
    fn new(
        socket: Arc<Mutex<UtpSocket>>,
        receiver: UnboundedReceiver<Result<()>>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Self {
        Self {
            socket,
            receiver,
            local,
            remote,
        }
    }

    /// Get the local address used by this `UtpStream`
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Get the address of the remote end of this `UtpStream`
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    fn handle_driver_notification(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        match poll_unpin!(self.receiver.recv(), cx) {
            // either driver sender was dropped or disconnection notice
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                debug!("connection driver has died");
                Poll::Ready(Ok(0))
            }
            Poll::Ready(Some(Ok(()))) => {
                debug!("notification from driver");
                self.poll_read(cx, buf)
            }
            Poll::Pending => {
                debug!("waiting for notification from driver");
                Poll::Pending
            }
        }
    }

    fn prepare_packet(socket: &mut UtpSocket, chunk: &[u8]) -> Packet {
        let mut packet = Packet::with_payload(chunk);

        packet.set_seq_nr(socket.seq_nr);
        packet.set_ack_nr(socket.ack_nr);
        packet.set_connection_id(socket.sender_connection_id);

        packet
    }

    fn wait_acks(
        socket: &mut UtpSocket,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        let mut buf = [0u8; BUF_SIZE + HEADER_SIZE];

        debug!("waiting for ACKs for {} packets", socket.send_window.len());

        while !socket.send_window.is_empty()
            && socket.state != SocketState::Closed
        {
            let (read, src) = {
                match poll_unpin!(socket.socket.recv_from(&mut buf), cx) {
                    Poll::Ready(Ok((read, src))) => (read, src),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            };

            let packet = Packet::try_from(&buf[..read])?;

            if let Some(reply) = socket.handle_packet(&packet, src)? {
                if let Poll::Pending =
                    poll_unpin!(socket.socket.send_to(reply.as_ref(), src), cx)
                {
                    socket.unsent_queue.push_back(reply);
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    fn flush_unsent(
        socket: &mut UtpSocket,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        while let Some(mut packet) = socket.unsent_queue.pop_front() {
            if let Poll::Pending =
                poll_unpin!(socket.send_packet(&mut packet), cx)
            {
                debug!("too many in flight packets, waiting for ack");
                return Poll::Pending;
            }

            let result = {
                let dst = socket.connected_to;
                poll_unpin!(socket.socket.send_to(packet.as_ref(), dst), cx)
            };

            match result {
                Poll::Pending => {
                    socket.unsent_queue.push_front(packet);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(_)) => socket.send_window.push(packet),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for UtpStream
where
    Self: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        debug!("read poll for {} bytes", buf.len());

        let (read, state) = {
            let mut socket = ready_unpin!(self.socket.lock(), cx);

            (socket.flush_incoming_buffer(buf), socket.state)
        };

        if read > 0 {
            debug!("flushed {} bytes of received data", read);
            Poll::Ready(Ok(read))
        } else if state == SocketState::Closed {
            debug!("read on closed connection");
            Poll::Ready(Ok(0))
        } else if state == SocketState::ResetReceived {
            debug!("read on reset connection");
            Poll::Ready(Err(SocketError::ConnectionReset.into()))
        } else {
            self.handle_driver_notification(cx, buf)
        }
    }
}

impl AsyncWrite for UtpStream
where
    Self: Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let mut socket = ready_unpin!(self.socket.lock(), cx);

        if socket.state == SocketState::Closed {
            debug!("tried to write on closed connection");
            return Poll::Ready(Err(SocketError::ConnectionClosed.into()));
        }

        let mut sent: usize = 0;

        debug!("trying to send {} bytes", buf.len());

        for chunk in buf.chunks(MSS as usize - HEADER_SIZE) {
            if socket.curr_window >= socket.max_inflight() {
                debug!("send window is full, waiting for ACKs");
                mem::drop(socket);

                while let Poll::Ready(_) = poll_unpin!(self.receiver.recv(), cx)
                {
                }

                return Poll::Pending;
            }

            debug!("attempting to send chunk of {} byte", chunk.len());

            let mut packet = Self::prepare_packet(&mut socket, chunk);

            match poll_unpin!(socket.send_packet(&mut packet), cx) {
                Poll::Pending if sent == 0 => {
                    debug!("socket send buffer is full, waiting..");
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) if sent == 0 => {
                    debug!("os error reading data: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending | Poll::Ready(Err(_)) => {
                    debug!("successfully sent {} bytes, sleeping...", sent);
                    return Poll::Ready(Ok(sent));
                }

                Poll::Ready(Ok(())) => {
                    let written = packet.len();

                    socket.curr_window += written as u32;
                    socket.send_window.push(packet);

                    sent += written;
                    socket.seq_nr = socket.seq_nr.wrapping_add(1);

                    debug!(
                        "poll_write sent seq {}, curr_window: {}",
                        socket.seq_nr - 1,
                        socket.curr_window
                    );
                }
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<()>> {
        debug!("attempting flush");

        match poll_unpin!(self.receiver.recv(), cx) {
            Poll::Ready(Some(Err(e))) => {
                debug!("driver signaled error over channel");
                return Poll::Ready(Err(e));
            }
            Poll::Ready(None) => {
                debug!("connection driver disconnected");
                return Poll::Ready(Ok(()));
            }
            _ => debug!("no message from driver"),
        }

        let mut socket = ready_unpin!(self.socket.lock(), cx);

        if socket.state == SocketState::Closed {
            return Poll::Ready(Err(SocketError::NotConnected.into()));
        }

        ready_try!(Self::flush_unsent(&mut socket, cx));

        ready_try!(Self::wait_acks(&mut socket, cx));

        debug!("sucessfully flushed");

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<()>> {
        debug!("poll_shutdown connection...");

        {
            let socket = ready_unpin!(self.socket.lock(), cx);

            if socket.state == SocketState::Closed {
                debug!("socket closed by driver");
                return Poll::Ready(Ok(()));
            }
        }

        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                {
                    let mut socket = ready_unpin!(self.socket.lock(), cx);

                    if socket.state != SocketState::FinSent {
                        if let Poll::Ready(Ok(())) =
                            poll_unpin!(socket.close(), cx)
                        {
                            return Poll::Ready(Ok(()));
                        } else {
                            mem::drop(socket);
                            ready_unpin!(self.receiver.recv(), cx);
                        }
                    }
                }

                let msg = poll_unpin!(self.receiver.recv(), cx);

                match msg {
                    Poll::Ready(None) => {
                        debug!("driver is dead, closing success");
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Some(Ok(()))) => {
                        debug!("driver sent closing notice");
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Some(Err(e)))
                        if e.kind() == ErrorKind::NotConnected =>
                    {
                        debug!("connection closed by err");
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Some(Err(e))) => {
                        debug!("failed to close correctly");
                        Poll::Ready(Err(e))
                    }
                    Poll::Pending => {
                        debug!("waiting for driver to complete closing");
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

#[must_use = "stream drivers must be spawned for the stream to work"]
/// This is a `Future` that takes care of handling all events related to
/// a `UtpStream`. `UtpStream` won't receive neither send any data until this
/// driver is spawned as a tokio task.
pub struct UtpStreamDriver {
    socket: Arc<Mutex<UtpSocket>>,
    sender: UnboundedSender<Result<()>>,
    timer: TokioDelay,
    timeout_nr: u32,
}

impl UtpStreamDriver {
    fn new(
        socket: Arc<Mutex<UtpSocket>>,
        sender: UnboundedSender<Result<()>>,
    ) -> Self {
        Self {
            socket,
            sender,
            timer: delay_for(Duration::from_millis(INITIAL_CONGESTION_TIMEOUT)),
            timeout_nr: 0,
        }
    }

    async fn handle_timeout(&mut self, next_timeout: u64) -> Result<()> {
        self.timeout_nr += 1;
        debug!(
            "timed out {} times out of {} max, retrying in {} ms",
            self.timeout_nr, MAX_RETRANSMISSION_RETRIES, next_timeout
        );

        if self.timeout_nr > MAX_RETRANSMISSION_RETRIES {
            let mut socket = self.socket.lock().await;
            socket.state = SocketState::Closed;

            return Err(SocketError::ConnectionTimedOut.into());
        }

        let ret = {
            let mut socket = self.socket.lock().await;
            socket.handle_receive_timeout().await
        };

        self.timer = delay_for(Duration::from_millis(next_timeout));

        ret
    }

    fn notify_close(&mut self) {
        if self
            .sender
            .send(Err(SocketError::NotConnected.into()))
            .is_err()
        {
            error!("failed to notify socket of termination");
        } else {
            debug!("notified socket of closing");
        }
    }

    fn send_reply(
        socket: &mut UtpSocket,
        mut reply: Packet,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        match poll_unpin!(socket.send_packet(&mut reply), cx) {
            Poll::Pending => {
                socket.unsent_queue.push_back(reply);
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                error!("driver failed to send packet: {}", e);
                Poll::Ready(Err(e))
            }
            _ => Poll::Ready(Ok(())),
        }
    }

    fn check_timeout(
        &mut self,
        cx: &mut Context<'_>,
        next_timeout: u64,
    ) -> Poll<Result<()>> {
        if self.timer.is_elapsed() {
            debug!("receive timeout detected");

            match poll_unpin!(self.handle_timeout(next_timeout), cx) {
                Poll::Pending => todo!("socket buffer full"),
                Poll::Ready(Ok(())) => {
                    let now: TokioInstant = Instant::now().into();

                    self.timer.reset(now + Duration::from_millis(next_timeout));
                    ready_unpin!(self.timer, cx);

                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    debug!("remote peer timed out too many times");
                    self.sender
                        .send(Err(e.kind().into()))
                        .expect("failed to propagate");

                    Poll::Ready(Err(e))
                }
            }
        } else {
            ready_unpin!(self.timer, cx);
            Poll::Pending
        }
    }
}

impl Future for UtpStreamDriver {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let sender = self.sender.clone();
        let mut socket = ready_unpin!(self.socket.lock(), cx);
        let mut buf = [0u8; BUF_SIZE + HEADER_SIZE];

        loop {
            debug!("stream driver poll attempt");

            if socket.state == SocketState::Closed {
                debug!("socket is closed when attempting poll, killing driver");

                mem::drop(socket);

                self.notify_close();

                return Poll::Ready(Ok(()));
            }

            match poll_unpin!(socket.socket.recv_from(&mut buf), cx) {
                Poll::Ready(Ok((read, src))) => {
                    if let Ok(packet) = Packet::try_from(&buf[..read]) {
                        debug!("received packet {:?}", packet);

                        match socket.handle_packet(&packet, src) {
                            Ok(Some(reply)) => {
                                if let PacketType::Data = packet.get_type() {
                                    socket.insert_into_buffer(packet);

                                    // notify socket that data is available
                                    if sender.send(Ok(())).is_err() {
                                        debug!(
                                            "dropped socket, killing driver"
                                        );
                                        return Poll::Ready(Ok(()));
                                    }
                                }

                                if let Poll::Pending =
                                    Self::send_reply(&mut socket, reply, cx)
                                {
                                    return Poll::Pending;
                                }
                            }
                            Ok(None) => ready_try_unpin!(socket.send(), cx),
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    let next_timeout = socket.congestion_timeout * 2;

                    mem::drop(socket);

                    return self.check_timeout(cx, next_timeout);
                }
            }
        }
    }
}

impl Drop for UtpSocket {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::io::ErrorKind;
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::socket::{SocketState, UtpSocket, BUF_SIZE};
    use crate::time::now_microseconds;

    use rand;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task;
    use tokio::time::interval;

    use tracing::debug_span;
    use tracing_futures::Instrument;
    use tracing_subscriber::FmtSubscriber;

    macro_rules! iotry {
        ($e:expr) => {
            match $e.await {
                Ok(e) => e,
                Err(e) => panic!("{:?}", e),
            }
        };
    }

    fn init_logger() {
        if let Some(level) = env::var("RUST_LOG").ok().map(|x| x.parse().ok()) {
            let subscriber =
                FmtSubscriber::builder().with_max_level(level).finish();

            let _ = tracing::subscriber::set_global_default(subscriber);
        }
    }

    fn next_test_port() -> u16 {
        use std::sync::atomic::AtomicUsize;
        static NEXT_OFFSET: AtomicUsize = AtomicUsize::new(0);
        const BASE_PORT: u16 = 9600;
        BASE_PORT + NEXT_OFFSET.fetch_add(1, Ordering::Relaxed) as u16
    }

    fn next_test_ip4() -> SocketAddr {
        ("127.0.0.1".parse::<Ipv4Addr>().unwrap(), next_test_port()).into()
    }

    fn next_test_ip6() -> SocketAddr {
        ("::1".parse::<Ipv6Addr>().unwrap(), next_test_port()).into()
    }

    async fn stream_accept(server_addr: SocketAddr) -> UtpStream {
        let (stream, driver) = UtpSocketRef::bind(server_addr)
            .await
            .expect("failed to bind")
            .accept()
            .await
            .expect("failed to accept");

        task::spawn(driver.instrument(debug_span!("stream_driver")));

        stream
    }

    async fn stream_connect(local: SocketAddr, peer: SocketAddr) -> UtpStream {
        let socket = UtpSocketRef::bind(local).await.expect("failed to bind");
        let (stream, driver) =
            socket.connect(peer).await.expect("failed to connect");

        task::spawn(driver.instrument(debug_span!("stream_driver")));

        stream
    }

    #[tokio::test]
    async fn stream_fast_resend_active() {
        init_logger();
        let server_addr = next_test_ip4();
        const DATA: u8 = 2;
        const LEN: usize = 345;

        let socket =
            UtpSocketRef::bind(server_addr).await.expect("bind failed");

        let handle = task::spawn(async {
            let buf = [DATA; LEN];
            let (mut stream, driver) =
                socket.accept().await.expect("accept failed");

            task::spawn(driver);

            stream.write_all(&buf).await.expect("write failed");
            stream.shutdown().await.expect("shutdown failed");
        });

        let mut socket = UtpSocket::connect(server_addr)
            .await
            .expect("connect failed");

        let mut buf = [0u8; LEN];

        // intentionaly drop the received packet to trigger fast_resend
        socket
            .socket
            .recv_from(&mut buf)
            .await
            .expect("read failed");

        socket.recv_from(&mut buf).await.expect("failed to resend");
        socket.close().await.expect("close failed");

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn stream_connect_disconnect() {
        init_logger();
        let server_addr = next_test_ip4();
        let client_addr = next_test_ip4();

        let handle = task::spawn(async move {
            let mut stream = stream_accept(server_addr).await;

            stream.shutdown().await.expect("failed to close");
        });

        let mut stream = stream_connect(client_addr, server_addr).await;

        stream.shutdown().await.expect("failed to close connection");

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn stream_packet_split() {
        init_logger();

        let server_addr = next_test_ip4();
        let client_addr = next_test_ip4();
        const LEN: usize = 2000;
        const DATA: u8 = 1;

        let handle = task::spawn(async move {
            let mut stream = stream_accept(server_addr)
                .instrument(debug_span!("server"))
                .await;

            let mut buf = [0u8; LEN];

            stream
                .read_exact(&mut buf)
                .instrument(debug_span!("server_read_exact"))
                .await
                .expect("read failed");

            for b in &buf[..] {
                assert_eq!(*b, DATA, "data was altered");
            }

            stream
                .shutdown()
                .instrument(debug_span!("server_shutdown"))
                .await
                .expect("flush failed");
        });

        let mut stream = stream_connect(client_addr, server_addr)
            .instrument(debug_span!("client"))
            .await;
        let buf = [DATA; LEN];

        stream
            .write_all(&buf)
            .instrument(debug_span!("client_write_all"))
            .await
            .expect("write failed");

        stream
            .shutdown()
            .instrument(debug_span!("client_shutdown"))
            .await
            .expect("close failed");

        handle.await.expect("task failure")
    }

    #[tokio::test]
    async fn stream_closed_write() {
        init_logger();
        let server_addr = next_test_ip4();
        let client_addr = next_test_ip4();

        const LEN: usize = 1240;
        const DATA: u8 = 12;

        let handle = task::spawn(async move {
            let mut stream = stream_accept(server_addr)
                .instrument(debug_span!("server"))
                .await;
            let mut buf = [0u8; LEN];

            stream
                .read_exact(&mut buf)
                .instrument(debug_span!("server_read_exact"))
                .await
                .expect("read failed");

            stream
                .shutdown()
                .instrument(debug_span!("server_shutdown"))
                .await
                .expect("shutdown failed");

            stream
                .read_exact(&mut buf)
                .instrument(debug_span!("server_closed_read"))
                .await
                .expect_err("read on closed stream");
        });

        let mut stream = stream_connect(client_addr, server_addr)
            .instrument(debug_span!("client"))
            .await;
        let buf = [DATA; LEN];

        stream
            .write_all(&buf)
            .instrument(debug_span!("client_write_all"))
            .await
            .expect("write failed");
        stream
            .shutdown()
            .instrument(debug_span!("client_shutdown"))
            .await
            .expect("shutdown failed");

        stream
            .write_all(&buf)
            .instrument(debug_span!("client_closed_write"))
            .await
            .expect_err("wrote on closed stream");

        handle.await.expect("execution failure");
    }

    #[tokio::test]
    async fn stream_fast_resend_idle() {
        init_logger();
        let server = next_test_ip4();
        let client = next_test_ip4();

        let handle = task::spawn(async move {
            let mut stream = stream_accept(server).await;

            let mut timer = interval(Duration::from_secs(3));

            timer.tick().await;

            stream.shutdown().await.expect("close failed");
        });

        let mut stream = stream_connect(client, server).await;
        let mut timer = interval(Duration::from_secs(4));

        timer.tick().await;

        stream.shutdown().await.expect("close failed");

        handle.await.expect("task failed");
    }

    #[tokio::test]
    async fn stream_clean_close() {
        init_logger();
        let server_addr = next_test_ip4();
        let client_addr = next_test_ip4();

        const DATA: u8 = 1;
        const LEN: usize = 1024;

        let handle = task::spawn(async move {
            let mut stream = stream_accept(server_addr)
                .instrument(debug_span!("stream_accept"))
                .await;
            let buf = [DATA; LEN];

            stream
                .write_all(&buf)
                .instrument(debug_span!("server_write"))
                .await
                .expect("write failed");

            stream
                .shutdown()
                .instrument(debug_span!("server_shutdown"))
                .await
                .expect("shutdown failed");
        });

        let mut socket = stream_connect(client_addr, server_addr)
            .instrument(debug_span!("stream_connect"))
            .await;
        let mut buf = [0u8; LEN];

        socket
            .read_exact(&mut buf)
            .instrument(debug_span!("client_read"))
            .await
            .expect("read failed");

        socket
            .shutdown()
            .instrument(debug_span!("client_shutdown"))
            .await
            .expect("shutdown failed");

        handle.await.expect("task panic");
    }

    #[tokio::test]
    async fn stream_connect_timeout() {
        init_logger();
        let server_addr = next_test_ip4();
        let client_addr = next_test_ip4();

        let socket =
            UtpSocketRef::bind(client_addr).await.expect("bind failed");

        socket.0.lock().await.congestion_timeout = 100;

        assert!(
            socket.connect(server_addr).await.is_err(),
            "connected to void"
        );
    }

    #[tokio::test]
    async fn stream_read_timeout() {
        init_logger();
        let server_addr = next_test_ip4();
        let client_addr = next_test_ip4();

        let handle = task::spawn(async move {
            let sock =
                UtpSocketRef::bind(server_addr).await.expect("bind failed");

            // ignore driver so that this stream doesn't answer to packets
            let _ = sock.accept().await.expect("accept failed");
        });

        let mut socket = stream_connect(client_addr, server_addr).await;
        let mut buf = [0u8; 1024];

        socket.socket.lock().await.congestion_timeout = 100;

        socket
            .read_exact(&mut buf)
            .await
            .expect_err("read from non responding peer");

        handle.await.expect("task panic");
    }

    #[tokio::test]
    async fn stream_write_timeout() {
        init_logger();

        let (server, client) = (next_test_ip4(), next_test_ip4());
        const DATA: u8 = 45;
        const LEN: usize = 123;

        let handle = task::spawn(async move {
            let mut stream = stream_accept(server).await;
            let buf = [DATA; LEN];

            stream.socket.lock().await.congestion_timeout = 100;

            stream
                .write_all(&buf)
                .await
                .expect("packets weren't buffered");
            stream
                .flush()
                .await
                .expect_err("flush succeeded without ack");
        });

        let sock = UtpSocketRef::bind(client).await.expect("bind failed");
        let _ = sock.connect(server).await.expect("connect failed");

        handle.await.expect("execution failure");
    }

    #[tokio::test]
    async fn stream_flush_then_send() {
        init_logger();
        let server_addr = next_test_ip4();
        let client_addr = next_test_ip4();

        const LEN: usize = 1240;
        const DATA: u8 = 25;

        let handle = task::spawn(async move {
            let mut stream = stream_accept(server_addr).await;
            let mut buf = [0u8; 2 * LEN];

            stream.read_exact(&mut buf).await.expect("failed to read");

            for b in buf.iter() {
                assert_eq!(*b, DATA, "data corrupted");
            }

            stream.flush().await.expect("flush failed");
            stream.shutdown().await.expect("shutdown failed");
        });

        let mut stream = stream_connect(client_addr, server_addr).await;
        let buf = [DATA; LEN];

        stream.write_all(&buf).await.expect("write failed");

        stream.flush().await.expect("flush failed");

        stream.write_all(&buf).await.expect("write failed");
        stream.shutdown().await.expect("shutdown failed");

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_socket_ipv4() {
        let server_addr = next_test_ip4();

        let handle = task::spawn(async move {
            let mut server = iotry!(UtpSocket::bind(server_addr));
            assert_eq!(server.state, SocketState::New);

            let mut buf = [0u8; BUF_SIZE];
            match server.recv_from(&mut buf).await {
                e => println!("{:?}", e),
            }
            // After establishing a new connection, the server's ids are a
            // mirror of the client's.
            assert_eq!(
                server.receiver_connection_id,
                server.sender_connection_id + 1
            );

            assert_eq!(server.state, SocketState::Closed);
            drop(server);
        });

        let mut client = iotry!(UtpSocket::connect(server_addr));
        assert_eq!(client.state, SocketState::Connected);
        // Check proper difference in client's send connection id and receive
        // connection id
        assert_eq!(
            client.sender_connection_id,
            client.receiver_connection_id + 1
        );
        assert_eq!(
            client.connected_to,
            server_addr.to_socket_addrs().unwrap().next().unwrap()
        );
        iotry!(client.close());

        handle.await.expect("task failure");
    }

    #[ignore]
    #[tokio::test]
    async fn test_socket_ipv6() {
        let server_addr = next_test_ip6();

        let mut server = iotry!(UtpSocket::bind(server_addr));
        assert_eq!(server.state, SocketState::New);

        task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            assert_eq!(client.state, SocketState::Connected);
            // Check proper difference in client's send connection id and
            // receive connection id
            assert_eq!(
                client.sender_connection_id,
                client.receiver_connection_id + 1
            );
            assert_eq!(
                client.connected_to,
                server_addr.to_socket_addrs().unwrap().next().unwrap()
            );
            iotry!(client.close());
            drop(client);
        });

        let mut buf = [0u8; BUF_SIZE];
        match server.recv_from(&mut buf).await {
            e => println!("{:?}", e),
        }
        // After establishing a new connection, the server's ids are a mirror of
        // the client's.
        assert_eq!(
            server.receiver_connection_id,
            server.sender_connection_id + 1
        );

        assert_eq!(server.state, SocketState::Closed);
        drop(server);
    }

    #[tokio::test]
    async fn test_recvfrom_on_closed_socket() {
        let server_addr = next_test_ip4();

        let mut server = iotry!(UtpSocket::bind(server_addr));
        assert_eq!(server.state, SocketState::New);

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            assert_eq!(client.state, SocketState::Connected);
            assert!(client.close().await.is_ok());
        });

        // Make the server listen for incoming connections until the end of the
        // input
        let mut buf = [0u8; BUF_SIZE];
        let _resp = server.recv_from(&mut buf).await;
        assert_eq!(server.state, SocketState::Closed);

        // Trying to receive again returns `Ok(0)` (equivalent to the old
        // `EndOfFile`)
        match server.recv_from(&mut buf).await {
            Ok((0, _src)) => {}
            e => panic!("Expected Ok(0), got {:?}", e),
        }
        assert_eq!(server.state, SocketState::Closed);

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_sendto_on_closed_socket() {
        let server_addr = next_test_ip4();

        let mut server = iotry!(UtpSocket::bind(server_addr));
        assert_eq!(server.state, SocketState::New);

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            assert_eq!(client.state, SocketState::Connected);
            iotry!(client.close());
        });

        // Make the server listen for incoming connections
        let mut buf = [0u8; BUF_SIZE];
        let (_read, _src) = iotry!(server.recv_from(&mut buf));
        assert_eq!(server.state, SocketState::Closed);

        // Trying to send to the socket after closing it raises an error
        match server.send_to(&buf).await {
            Err(ref e) if e.kind() == ErrorKind::NotConnected => (),
            v => panic!("expected {:?}, got {:?}", ErrorKind::NotConnected, v),
        }

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_acks_on_socket() {
        use std::sync::mpsc::channel;
        let server_addr = next_test_ip4();
        let (tx, rx) = channel();

        let mut server = iotry!(UtpSocket::bind(server_addr));

        let handle = task::spawn(async move {
            // Make the server listen for incoming connections
            let mut buf = [0u8; BUF_SIZE];
            let _resp = server.recv(&mut buf).await.unwrap();
            tx.send(server.seq_nr).unwrap();

            // Close the connection
            iotry!(server.recv_from(&mut buf));
        });

        let mut client = iotry!(UtpSocket::connect(server_addr));
        assert_eq!(client.state, SocketState::Connected);
        let sender_seq_nr = rx.recv().unwrap();
        let ack_nr = client.ack_nr;
        assert_eq!(ack_nr, sender_seq_nr);
        assert!(client.close().await.is_ok());

        // The reply to both connect (SYN) and close (FIN) should be
        // STATE packets, which don't increase the sequence number
        // and, hence, the receiver's acknowledgement number.
        assert_eq!(client.ack_nr, ack_nr);
        drop(client);

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_handle_packet() {
        //fn test_connection_setup() {
        let initial_connection_id: u16 = rand::random();
        let sender_connection_id = initial_connection_id + 1;
        let (server_addr, client_addr) = (
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
        );
        let mut socket = iotry!(UtpSocket::bind(server_addr));

        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(initial_connection_id);

        // Do we have a response?
        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        // Is is of the correct type?
        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::State);

        // Same connection id on both ends during connection establishment
        assert_eq!(response.connection_id(), packet.connection_id());

        // Response acknowledges SYN
        assert_eq!(response.ack_nr(), packet.seq_nr());

        // No payload?
        assert!(response.payload().is_empty());
        //}

        // ---------------------------------

        // fn test_connection_usage() {
        let old_packet = packet;
        let old_response = response;

        let mut packet = Packet::new();
        packet.set_type(PacketType::Data);
        packet.set_connection_id(sender_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 1);
        packet.set_ack_nr(old_response.seq_nr());

        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::State);

        // Sender (i.e., who the initiated connection and sent a SYN) has
        // connection id equal to initial connection id + 1
        // Receiver (i.e., who accepted connection) has connection id equal to
        // initial connection id
        assert_eq!(response.connection_id(), initial_connection_id);
        assert_eq!(response.connection_id(), packet.connection_id() - 1);

        // Previous packets should be ack'ed
        assert_eq!(response.ack_nr(), packet.seq_nr());

        // Responses with no payload should not increase the sequence number
        assert!(response.payload().is_empty());
        assert_eq!(response.seq_nr(), old_response.seq_nr());
        // }

        //fn test_connection_teardown() {
        let old_packet = packet;
        let old_response = response;

        let mut packet = Packet::new();
        packet.set_type(PacketType::Fin);
        packet.set_connection_id(sender_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 1);
        packet.set_ack_nr(old_response.seq_nr());

        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        let response = response.unwrap();

        assert_eq!(response.get_type(), PacketType::State);

        // FIN packets have no payload but the sequence number shouldn't increase
        assert_eq!(packet.seq_nr(), old_packet.seq_nr() + 1);

        // Nor should the ACK packet's sequence number
        assert_eq!(response.seq_nr(), old_response.seq_nr());

        // FIN should be acknowledged
        assert_eq!(response.ack_nr(), packet.seq_nr());
    }

    #[tokio::test]
    async fn test_response_to_keepalive_ack() {
        // Boilerplate test setup
        let initial_connection_id: u16 = rand::random();
        let (server_addr, client_addr) = (
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
        );
        let mut socket = iotry!(UtpSocket::bind(server_addr));

        // Establish connection
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(initial_connection_id);

        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());
        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::State);

        let old_packet = packet;
        let old_response = response;

        // Now, send a keepalive packet
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::State);
        packet.set_connection_id(initial_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 1);
        packet.set_ack_nr(old_response.seq_nr());

        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_none());

        // Send a second keepalive packet, identical to the previous one
        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_none());

        // Mark socket as closed
        socket.state = SocketState::Closed;
    }

    #[tokio::test]
    async fn test_response_to_wrong_connection_id() {
        // Boilerplate test setup
        let initial_connection_id: u16 = rand::random();
        let (server_addr, client_addr) = (
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
        );
        let mut socket = iotry!(UtpSocket::bind(server_addr));

        // Establish connection
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(initial_connection_id);

        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().get_type(), PacketType::State);

        // Now, disrupt connection with a packet with an incorrect connection id
        let new_connection_id = initial_connection_id.wrapping_mul(2);

        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::State);
        packet.set_connection_id(new_connection_id);

        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::Reset);
        assert_eq!(response.ack_nr(), packet.seq_nr());

        // Mark socket as closed
        socket.state = SocketState::Closed;
    }

    #[tokio::test]
    async fn test_unordered_packets() {
        // Boilerplate test setup
        let initial_connection_id: u16 = rand::random();
        let (server_addr, client_addr) = (
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
        );
        let mut socket = iotry!(UtpSocket::bind(server_addr));

        // Establish connection
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(initial_connection_id);

        let response = socket.handle_packet(&packet, client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());
        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::State);

        let old_packet = packet;
        let old_response = response;

        let mut window: Vec<Packet> = Vec::new();

        // Now, send a keepalive packet
        let mut packet = Packet::with_payload(&[1, 2, 3]);
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_connection_id(initial_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 1);
        packet.set_ack_nr(old_response.seq_nr());
        window.push(packet);

        let mut packet = Packet::with_payload(&[4, 5, 6]);
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_connection_id(initial_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 2);
        packet.set_ack_nr(old_response.seq_nr());
        window.push(packet);

        // Send packets in reverse order
        let response = socket.handle_packet(&window[1], client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());
        let response = response.unwrap();
        assert!(response.ack_nr() != window[1].seq_nr());

        let response = socket.handle_packet(&window[0], client_addr);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        // Mark socket as closed
        socket.state = SocketState::Closed;
    }

    #[tokio::test]
    async fn test_response_to_triple_ack() {
        let server_addr = next_test_ip4();
        let mut server = iotry!(UtpSocket::bind(server_addr));

        // Fits in a packet
        const LEN: usize = 1024;
        let data = (0..LEN).map(|idx| idx as u8).collect::<Vec<u8>>();
        let d = data.clone();
        assert_eq!(LEN, data.len());

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            iotry!(client.send_to(&d[..]));
            iotry!(client.close());
        });

        let mut buf = [0; BUF_SIZE];
        // Expect SYN
        iotry!(server.recv(&mut buf));

        // Receive data
        let data_packet = match server.socket.recv_from(&mut buf).await {
            Ok((read, _src)) => Packet::try_from(&buf[..read]).unwrap(),
            Err(e) => panic!("{}", e),
        };
        assert_eq!(data_packet.get_type(), PacketType::Data);
        assert_eq!(&data_packet.payload(), &data.as_slice());
        assert_eq!(data_packet.payload().len(), data.len());

        // Send triple ACK
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::State);
        packet.set_seq_nr(server.seq_nr);
        packet.set_ack_nr(data_packet.seq_nr() - 1);
        packet.set_connection_id(server.sender_connection_id);

        for _ in 0..3usize {
            iotry!(server.socket.send_to(packet.as_ref(), server.connected_to));
        }

        // Receive data again and check that it's the same we reported as missing
        let client_addr = server.connected_to;
        match server.socket.recv_from(&mut buf).await {
            Ok((0, _)) => panic!("Received 0 bytes from socket"),
            Ok((read, _src)) => {
                let packet = Packet::try_from(&buf[..read]).unwrap();
                assert_eq!(packet.get_type(), PacketType::Data);
                assert_eq!(packet.seq_nr(), data_packet.seq_nr());
                assert_eq!(packet.payload(), data_packet.payload());
                let response = server.handle_packet(&packet, client_addr);
                assert!(response.is_ok());
                let response = response.unwrap();
                assert!(response.is_some());
                let response = response.unwrap();
                iotry!(server
                    .socket
                    .send_to(response.as_ref(), server.connected_to));
            }
            Err(e) => panic!("{}", e),
        }

        // Receive close
        iotry!(server.recv_from(&mut buf));

        handle.await.expect("task failure");
    }

    #[ignore]
    #[tokio::test]
    async fn test_socket_timeout_request() {
        let (server_addr, client_addr) = (
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
            next_test_ip4().to_socket_addrs().unwrap().next().unwrap(),
        );

        let client = iotry!(UtpSocket::bind(client_addr));
        let mut server = iotry!(UtpSocket::bind(server_addr));
        const LEN: usize = 512;
        let data = (0..LEN).map(|idx| idx as u8).collect::<Vec<u8>>();
        let d = data.clone();

        assert_eq!(server.state, SocketState::New);
        assert_eq!(client.state, SocketState::New);

        // Check proper difference in client's send connection id and receive
        // connection id
        assert_eq!(
            client.sender_connection_id,
            client.receiver_connection_id + 1
        );

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            assert_eq!(client.state, SocketState::Connected);
            assert_eq!(client.connected_to, server_addr);
            iotry!(client.send_to(&d[..]));
            drop(client);
        });

        let mut buf = [0u8; BUF_SIZE];
        server.recv(&mut buf).await.unwrap();
        // After establishing a new connection, the server's ids are a mirror of
        // the client's.
        assert_eq!(
            server.receiver_connection_id,
            server.sender_connection_id + 1
        );

        assert_eq!(server.state, SocketState::Connected);

        // Purposefully read from UDP socket directly and discard it, in order
        // to behave as if the packet was lost and thus trigger the timeout
        // handling in the *next* call to `UtpSocket.recv_from`.
        iotry!(server.socket.recv_from(&mut buf));

        // Set a much smaller than usual timeout, for quicker test completion
        server.congestion_timeout = 50;

        // Now wait for the previously discarded packet
        loop {
            match server.recv_from(&mut buf).await {
                Ok((0, _)) => continue,
                Ok(_) => break,
                Err(e) => panic!("{}", e),
            }
        }

        drop(server);

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_sorted_buffer_insertion() {
        let server_addr = next_test_ip4();
        let mut socket = iotry!(UtpSocket::bind(server_addr));

        let mut packet = Packet::new();
        packet.set_seq_nr(1);

        assert!(socket.incoming_buffer.is_empty());

        socket.insert_into_buffer(packet.clone());
        assert_eq!(socket.incoming_buffer.len(), 1);

        packet.set_seq_nr(2);
        packet.set_timestamp(128.into());

        socket.insert_into_buffer(packet.clone());
        assert_eq!(socket.incoming_buffer.len(), 2);
        assert_eq!(socket.incoming_buffer[1].seq_nr(), 2);
        assert_eq!(socket.incoming_buffer[1].timestamp(), 128.into());

        packet.set_seq_nr(3);
        packet.set_timestamp(256.into());

        socket.insert_into_buffer(packet.clone());
        assert_eq!(socket.incoming_buffer.len(), 3);
        assert_eq!(socket.incoming_buffer[2].seq_nr(), 3);
        assert_eq!(socket.incoming_buffer[2].timestamp(), 256.into());

        // Replacing a packet with a more recent version doesn't work
        packet.set_seq_nr(2);
        packet.set_timestamp(456.into());

        socket.insert_into_buffer(packet);
        assert_eq!(socket.incoming_buffer.len(), 3);
        assert_eq!(socket.incoming_buffer[1].seq_nr(), 2);
        assert_eq!(socket.incoming_buffer[1].timestamp(), 128.into());
    }

    #[tokio::test]
    async fn test_duplicate_packet_handling() {
        let (server_addr, client_addr) = (next_test_ip4(), next_test_ip4());

        let client = iotry!(UtpSocket::bind(client_addr));
        let mut server = iotry!(UtpSocket::bind(server_addr));

        assert_eq!(server.state, SocketState::New);
        assert_eq!(client.state, SocketState::New);

        // Check proper difference in client's send connection id and receive
        // connection id
        assert_eq!(
            client.sender_connection_id,
            client.receiver_connection_id + 1
        );

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            assert_eq!(client.state, SocketState::Connected);

            let mut packet = Packet::with_payload(&[1, 2, 3]);
            packet.set_wnd_size(BUF_SIZE as u32);
            packet.set_connection_id(client.sender_connection_id);
            packet.set_seq_nr(client.seq_nr);
            packet.set_ack_nr(client.ack_nr);

            // Send two copies of the packet, with different timestamps
            for _ in 0..2usize {
                packet.set_timestamp(now_microseconds());
                iotry!(client.socket.send_to(packet.as_ref(), server_addr));
            }
            client.seq_nr += 1;

            // Receive one ACK
            for _ in 0..1usize {
                let mut buf = [0; BUF_SIZE];
                iotry!(client.socket.recv_from(&mut buf));
            }

            iotry!(client.close());
        });
        let mut buf = [0u8; BUF_SIZE];
        iotry!(server.recv(&mut buf));
        // After establishing a new connection, the server's ids are a mirror of
        // the client's.
        assert_eq!(
            server.receiver_connection_id,
            server.sender_connection_id + 1
        );

        assert_eq!(server.state, SocketState::Connected);

        let expected: Vec<u8> = vec![1, 2, 3];
        let mut received: Vec<u8> = vec![];
        loop {
            match server.recv_from(&mut buf).await {
                Ok((0, _src)) => break,
                Ok((len, _src)) => received.extend(buf[..len].to_vec()),
                Err(e) => panic!("{:?}", e),
            }
        }
        assert_eq!(received.len(), expected.len());
        assert_eq!(received, expected);

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_correct_packet_loss() {
        let server_addr = next_test_ip4();

        let mut server = iotry!(UtpSocket::bind(server_addr));
        const LEN: usize = 1024 * 10;
        let data = (0..LEN).map(|idx| idx as u8).collect::<Vec<u8>>();
        let to_send = data.clone();

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));

            // Send everything except the odd chunks
            let chunks = to_send[..].chunks(BUF_SIZE);
            let dst = client.connected_to;
            for (index, chunk) in chunks.enumerate() {
                let mut packet = Packet::with_payload(chunk);
                packet.set_seq_nr(client.seq_nr);
                packet.set_ack_nr(client.ack_nr);
                packet.set_connection_id(client.sender_connection_id);
                packet.set_timestamp(now_microseconds());

                if index % 2 == 0 {
                    iotry!(client.socket.send_to(packet.as_ref(), dst));
                }

                client.curr_window += packet.len() as u32;
                client.send_window.push(packet);
                client.seq_nr += 1;
            }

            iotry!(client.close());
        });

        let mut buf = [0; BUF_SIZE];
        let mut received: Vec<u8> = vec![];
        loop {
            match server.recv_from(&mut buf).await {
                Ok((0, _src)) => break,
                Ok((len, _src)) => received.extend(buf[..len].to_vec()),
                Err(e) => panic!("{}", e),
            }
        }
        assert_eq!(received.len(), data.len());
        assert_eq!(received, data);
        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_tolerance_to_small_buffers() {
        let server_addr = next_test_ip4();
        let mut server = iotry!(UtpSocket::bind(server_addr));
        const LEN: usize = 1024;
        let data = (0..LEN).map(|idx| idx as u8).collect::<Vec<u8>>();
        let to_send = data.clone();

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            iotry!(client.send_to(&to_send[..]));
            iotry!(client.close());
        });

        let mut read = Vec::new();
        while server.state != SocketState::Closed {
            let mut small_buffer = [0; 512];
            match server.recv_from(&mut small_buffer).await {
                Ok((0, _src)) => break,
                Ok((len, _src)) => read.extend(small_buffer[..len].to_vec()),
                Err(e) => panic!("{}", e),
            }
        }

        assert_eq!(read.len(), data.len());
        assert_eq!(read, data);
        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_sequence_number_rollover() {
        let (server_addr, client_addr) = (next_test_ip4(), next_test_ip4());

        let mut server = iotry!(UtpSocket::bind(server_addr));

        const LEN: usize = BUF_SIZE * 4;
        let data = (0..LEN).map(|idx| idx as u8).collect::<Vec<u8>>();
        let to_send = data.clone();

        let mut client = iotry!(UtpSocket::bind(client_addr));

        // Advance socket's sequence number
        client.seq_nr =
            ::std::u16::MAX - (to_send.len() / (BUF_SIZE * 2)) as u16;

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            // Send enough data to rollover
            iotry!(client.send_to(&to_send[..]));
            // Check that the sequence number did rollover
            assert!(client.seq_nr < 50);
            // Close connection
            iotry!(client.close());
        });

        let mut buf = [0; BUF_SIZE];
        let mut received: Vec<u8> = vec![];
        loop {
            match server.recv_from(&mut buf).await {
                Ok((0, _src)) => break,
                Ok((len, _src)) => received.extend(buf[..len].to_vec()),
                Err(e) => panic!("{}", e),
            }
        }
        assert_eq!(received.len(), data.len());
        assert_eq!(received, data);
        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_drop_unused_socket() {
        let server_addr = next_test_ip4();
        let server = iotry!(UtpSocket::bind(server_addr));

        // Explicitly dropping socket. This test should not hang.
        drop(server);
    }

    #[tokio::test]
    async fn test_invalid_packet_on_connect() {
        use tokio::net::UdpSocket;
        let server_addr = next_test_ip4();
        let mut server = iotry!(UdpSocket::bind(server_addr));

        let handle = task::spawn(async move {
            match UtpSocket::connect(server_addr).await {
                Err(ref e) if e.kind() == ErrorKind::Other => (), // OK
                Err(e) => panic!("Expected ErrorKind::Other, got {:?}", e),
                Ok(_) => panic!("Expected Err, got Ok"),
            }
        });

        let mut buf = [0; BUF_SIZE];
        match server.recv_from(&mut buf).await {
            Ok((_len, client_addr)) => {
                iotry!(server.send_to(&[], client_addr));
            }
            _ => panic!(),
        }

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_receive_unexpected_reply_type_on_connect() {
        use tokio::net::UdpSocket;
        let server_addr = next_test_ip4();
        let mut server = iotry!(UdpSocket::bind(server_addr));

        let mut buf = [0; BUF_SIZE];
        let mut packet = Packet::new();
        packet.set_type(PacketType::Data);

        let handle = task::spawn(async move {
            match server.recv_from(&mut buf).await {
                Ok((_len, client_addr)) => {
                    iotry!(server.send_to(packet.as_ref(), client_addr));
                }
                _ => panic!(),
            }
        });

        match UtpSocket::connect(server_addr).await {
            Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => (), // OK
            Err(e) => {
                panic!("Expected ErrorKind::ConnectionRefused, got {:?}", e)
            }
            Ok(_) => panic!("Expected Err, got Ok"),
        }

        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_receiving_syn_on_established_connection() {
        // Establish connection
        let server_addr = next_test_ip4();
        let mut server = iotry!(UtpSocket::bind(server_addr));

        let handle = task::spawn(async move {
            let mut buf = [0; BUF_SIZE];
            loop {
                match server.recv_from(&mut buf).await {
                    Ok((0, _src)) => break,
                    Ok(_) => (),
                    Err(e) => panic!("{:?}", e),
                }
            }
        });

        let mut client = iotry!(UtpSocket::connect(server_addr));
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(client.sender_connection_id);
        packet.set_seq_nr(client.seq_nr);
        packet.set_ack_nr(client.ack_nr);
        iotry!(client.socket.send_to(packet.as_ref(), server_addr));
        let mut buf = [0; BUF_SIZE];
        match client.socket.recv_from(&mut buf).await {
            Ok((len, _src)) => {
                let reply = Packet::try_from(&buf[..len]).ok().unwrap();
                assert_eq!(reply.get_type(), PacketType::Reset);
            }
            Err(e) => panic!("{:?}", e),
        }
        iotry!(client.close());
        handle.await.expect("task failure");
    }

    #[tokio::test]
    async fn test_receiving_reset_on_established_connection() {
        // Establish connection
        let server_addr = next_test_ip4();
        let mut server = iotry!(UtpSocket::bind(server_addr));

        let handle = task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            let mut packet = Packet::new();
            packet.set_wnd_size(BUF_SIZE as u32);
            packet.set_type(PacketType::Reset);
            packet.set_connection_id(client.sender_connection_id);
            packet.set_seq_nr(client.seq_nr);
            packet.set_ack_nr(client.ack_nr);
            iotry!(client.socket.send_to(packet.as_ref(), server_addr));

            let mut buf = [0; BUF_SIZE];

            match client.socket.recv_from(&mut buf).await {
                Ok((_len, _src)) => (),
                Err(e) => panic!("{:?}", e),
            }
        });

        let mut buf = [0; BUF_SIZE];
        loop {
            match server.recv_from(&mut buf).await {
                Ok((0, _src)) => break,
                Ok(_) => (),
                Err(ref e) if e.kind() == ErrorKind::ConnectionReset => {
                    handle.await.expect("task failure");
                    return;
                }
                Err(e) => panic!("{:?}", e),
            }
        }
        panic!("Should have received Reset");
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn test_premature_fin() {
        let (server_addr, client_addr) = (next_test_ip4(), next_test_ip4());
        let mut server = iotry!(UtpSocket::bind(server_addr));

        const LEN: usize = BUF_SIZE * 4;
        let data = (0..LEN).map(|idx| idx as u8).collect::<Vec<u8>>();
        let to_send = data.clone();

        task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            iotry!(client.send_to(&to_send[..]));
            iotry!(client.close());
        });

        let mut buf = [0; BUF_SIZE];

        // Accept connection
        iotry!(server.recv(&mut buf));

        // Send FIN without acknowledging packets received
        let mut packet = Packet::new();
        packet.set_connection_id(server.sender_connection_id);
        packet.set_seq_nr(server.seq_nr);
        packet.set_ack_nr(server.ack_nr);
        packet.set_timestamp(now_microseconds());
        packet.set_type(PacketType::Fin);
        iotry!(server.socket.send_to(packet.as_ref(), client_addr));

        // Receive until end
        let mut received: Vec<u8> = vec![];
        loop {
            match server.recv_from(&mut buf).await {
                Ok((0, _src)) => break,
                Ok((len, _src)) => received.extend(buf[..len].to_vec()),
                Err(e) => panic!("{}", e),
            }
        }
        assert_eq!(received.len(), data.len());
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn test_base_delay_calculation() {
        let minute_in_microseconds = 60 * 10i64.pow(6);
        let samples = vec![
            (0, 10),
            (1, 8),
            (2, 12),
            (3, 7),
            (minute_in_microseconds + 1, 11),
            (minute_in_microseconds + 2, 19),
            (minute_in_microseconds + 3, 9),
        ];
        let addr = next_test_ip4();
        let mut socket = UtpSocket::bind(addr).await.unwrap();

        for (timestamp, delay) in samples {
            socket.update_base_delay(
                delay.into(),
                ((timestamp + delay) as u32).into(),
            );
        }

        let expected = vec![7i64, 9i64]
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let actual = socket.base_delays.iter().cloned().collect::<Vec<_>>();
        assert_eq!(expected, actual);
        assert_eq!(
            socket.min_base_delay(),
            expected.iter().min().cloned().unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn test_local_addr() {
        let addr = next_test_ip4();
        let addr = addr.to_socket_addrs().unwrap().next().unwrap();
        let socket = UtpSocket::bind(addr).await.unwrap();

        assert!(socket.local_addr().is_ok());
        assert_eq!(socket.local_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn test_peer_addr() {
        use std::sync::mpsc::channel;
        let addr = next_test_ip4();
        let server_addr = addr.to_socket_addrs().unwrap().next().unwrap();
        let mut server = UtpSocket::bind(server_addr).await.unwrap();
        let (tx, rx) = channel();

        // `peer_addr` should return an error because the socket isn't connected
        // yet
        assert!(server.peer_addr().is_err());

        task::spawn(async move {
            let mut client = iotry!(UtpSocket::connect(server_addr));
            let mut buf = [0; 1024];
            tx.send(client.local_addr())
                .expect("failed to send on channel");
            iotry!(client.recv_from(&mut buf));

            // Wait for a connection to be established
            let mut buf = [0; 1024];
            iotry!(server.recv(&mut buf));

            // `peer_addr` should succeed and be equal to the client's address
            assert!(server.peer_addr().is_ok());
            // The client is expected to be bound to "0.0.0.0", so we can only check if the port is
            // correct
            let client_addr = rx.recv().unwrap().unwrap();
            assert_eq!(server.peer_addr().unwrap().port(), client_addr.port());

            // Close the connection
            iotry!(server.close());

            // `peer_addr` should now return an error because the socket is closed
            assert!(server.peer_addr().is_err());
        });
    }

    // Test reaction to connection loss when sending data packets
    #[ignore]
    #[tokio::test]
    async fn test_connection_loss_data() {
        let server_addr = next_test_ip4();
        let mut server = iotry!(UtpSocket::bind(server_addr));
        // Decrease timeouts for faster tests
        server.congestion_timeout = 1;
        let attempts = server.max_retransmission_retries;

        let mut client = iotry!(UtpSocket::connect(server_addr));
        iotry!(client.send_to(&[0]));
        // Simulate connection loss by killing the socket.
        client.state = SocketState::Closed;

        let mut buf = [0; BUF_SIZE];
        iotry!(client.socket.recv_from(&mut buf));

        for _ in 0..attempts {
            match client.socket.recv_from(&mut buf).await {
                Ok((len, _src)) => assert_eq!(
                    Packet::try_from(&buf[..len]).unwrap().get_type(),
                    PacketType::Data
                ),
                Err(e) => panic!("{}", e),
            }
        }

        // Drain incoming packets
        let mut buf = [0; BUF_SIZE];
        iotry!(server.recv_from(&mut buf));

        iotry!(server.send_to(&[0]));

        // Try to receive ACKs, time out too many times on flush, and fail with
        // `TimedOut`
        let mut buf = [0; BUF_SIZE];
        match server.recv(&mut buf).await {
            Err(ref e) if e.kind() == ErrorKind::TimedOut => (),
            x => panic!("Expected Err(TimedOut), got {:?}", x),
        }
    }

    // Test reaction to connection loss when sending FIN
    #[ignore]
    #[tokio::test]
    async fn test_connection_loss_fin() {
        let server_addr = next_test_ip4();
        let mut server = iotry!(UtpSocket::bind(server_addr));
        // Decrease timeouts for faster tests
        server.congestion_timeout = 1;
        let attempts = server.max_retransmission_retries;

        let mut client = iotry!(UtpSocket::connect(server_addr));
        iotry!(client.send_to(&[0]));
        // Simulate connection loss by killing the socket.
        client.state = SocketState::Closed;
        let mut buf = [0; BUF_SIZE];
        iotry!(client.socket.recv_from(&mut buf));
        for _ in 0..attempts {
            match client.socket.recv_from(&mut buf).await {
                Ok((len, _src)) => assert_eq!(
                    Packet::try_from(&buf[..len]).unwrap().get_type(),
                    PacketType::Fin
                ),
                Err(e) => panic!("{}", e),
            }
        }

        // Drain incoming packets
        let mut buf = [0; BUF_SIZE];
        iotry!(server.recv_from(&mut buf));

        // Send FIN, time out too many times, and fail with `TimedOut`
        match server.close().await {
            Err(ref e) if e.kind() == ErrorKind::TimedOut => (),
            x => panic!("Expected Err(TimedOut), got {:?}", x),
        }
    }

    // Test reaction to connection loss when waiting for data packets
    #[ignore]
    #[tokio::test]
    async fn test_connection_loss_waiting() {
        let server_addr = next_test_ip4();
        let mut server = iotry!(UtpSocket::bind(server_addr));
        // Decrease timeouts for faster tests
        server.congestion_timeout = 1;
        let attempts = server.max_retransmission_retries;

        let mut client = iotry!(UtpSocket::connect(server_addr));
        iotry!(client.send_to(&[0]));
        // Simulate connection loss by killing the socket.
        client.state = SocketState::Closed;
        let seq_nr = client.seq_nr;
        let mut buf = [0; BUF_SIZE];
        for _ in 0..(3 * attempts) {
            match client.socket.recv_from(&mut buf).await {
                Ok((len, _src)) => {
                    let packet = Packet::try_from(&buf[..len]).unwrap();
                    assert_eq!(packet.get_type(), PacketType::State);
                    assert_eq!(packet.ack_nr(), seq_nr - 1);
                }
                Err(e) => panic!("{}", e),
            }
        }

        // Drain incoming packets
        let mut buf = [0; BUF_SIZE];
        iotry!(server.recv_from(&mut buf));

        // Try to receive data, time out too many times, and fail with `TimedOut`
        let mut buf = [0; BUF_SIZE];
        match server.recv_from(&mut buf).await {
            Err(ref e) if e.kind() == ErrorKind::TimedOut => (),
            x => panic!("Expected Err(TimedOut), got {:?}", x),
        }
    }
}
