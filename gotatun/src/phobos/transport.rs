//! Phobos as a [`UdpTransportFactory`] wrapper, client side. See
//! [`PhobosUdpFactory`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Buf;
#[cfg(feature = "mock_instant")]
use mock_instant::thread_local::Instant;
use parking_lot::Mutex;

#[cfg(not(feature = "mock_instant"))]
use crate::sleepyinstant::Instant;

use super::{ConfigError, PhobosCodec, PhobosConfig, Unwrapped};
use crate::packet::{Packet, PacketBufPool};
use crate::task::Task;
use crate::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};

/// How recent the last handshake response must be for the periodic Binding
/// Request to run: WireGuard's `REJECT_AFTER_TIME`, past which the session
/// is unusable anyway.
pub const CONTROL_SESSION_WINDOW: Duration = Duration::from_secs(180);

/// WireGuard message type of a handshake initiation.
const HANDSHAKE_INITIATION: u8 = 1;
/// WireGuard message type of a handshake response.
const HANDSHAKE_RESPONSE: u8 = 2;

/// Whether `datagram` starts with the plain WireGuard type field `t`.
fn has_type(datagram: &[u8], t: u8) -> bool {
    datagram.len() >= 4 && datagram[..4] == [t, 0, 0, 0]
}

/// State shared by the factory, its send and receive halves, the control
/// task and the [`PhobosHandle`].
struct Shared {
    /// The codec and a scratch buffer to wrap into. Locked for one wrap or
    /// unwrap, never across an `await`.
    codec: Mutex<CodecState>,
    /// The newest generation: bumped by every `bind` and by
    /// [`PhobosHandle::address_changed`]. 0 before the first bind.
    generation: AtomicU64,
    /// The generation the newest `bind` started. A send half bound then is
    /// the current socket; any other is an old one being torn down.
    bound: AtomicU64,
    /// The newest generation an initiation has been sent on successfully.
    initiated: AtomicU64,
    /// The newest generation an initiation has been handed to the socket on,
    /// whether or not that send has finished. A datagram held back after it
    /// does not ask for another: the one in flight either opens the gate or
    /// fails and asks itself, and the tunnel retries a lost one on its own.
    attempted: AtomicU64,
    /// Raised when the device should send a handshake initiation.
    needs_initiation: AtomicBool,
    /// When the newest handshake response was seen.
    last_handshake: Mutex<Option<Instant>>,
    /// Where WireGuard last sent to: the server, for the control traffic.
    last_destination: Mutex<Option<SocketAddr>>,
}

struct CodecState {
    codec: PhobosCodec,
    scratch: Vec<u8>,
}

impl Shared {
    fn request_initiation(&self) {
        self.needs_initiation.store(true, Ordering::Release);
    }

    fn gate_closed(&self, generation: u64) -> bool {
        self.initiated.load(Ordering::Acquire) < generation
    }

    fn saw_handshake(&self) {
        *self.last_handshake.lock() = Some(Instant::now());
    }

    fn session_recent(&self) -> bool {
        self.last_handshake
            .lock()
            .is_some_and(|t| t.elapsed() < CONTROL_SESSION_WINDOW)
    }
}

/// The device's side of a [`PhobosUdpFactory`]: through it, the transport
/// asks for a handshake initiation.
///
/// Register it with
/// [`DeviceBuilder::with_phobos_handle`](crate::device::DeviceBuilder::with_phobos_handle)
/// when building the device over the factory by hand.
/// [`DeviceBuilder::with_phobos`](crate::device::DeviceBuilder::with_phobos)
/// does both.
#[derive(Clone)]
pub struct PhobosHandle(Arc<Shared>);

impl PhobosHandle {
    /// Whether the transport needs a handshake initiation sent: a new socket
    /// was bound, [`address_changed`](Self::address_changed) was called, an
    /// initiation failed to send, or a datagram was dropped before any
    /// initiation was tried on the current address. Clears the request.
    pub(crate) fn take_initiation_request(&self) -> bool {
        self.0.needs_initiation.swap(false, Ordering::AcqRel)
    }

    /// Report that the local address or path changed without a new
    /// [`bind`](UdpTransportFactory::bind): a route change, a NAT rebinding,
    /// or an embedder switching the socket's path underneath the factory.
    ///
    /// The Phobos server sees a new source address and drops everything
    /// from it but a handshake initiation. So this starts a new generation:
    /// the current socket's gate closes until an initiation has been sent on
    /// it, and the device is asked for one. An embedder whose transport can
    /// change its local address or path without rebinding must call this
    /// whenever it does.
    pub fn address_changed(&self) {
        self.0.generation.fetch_add(1, Ordering::AcqRel);
        self.0.request_initiation();
    }
}

impl std::fmt::Debug for PhobosHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhobosHandle")
            .field("generation", &self.0.generation.load(Ordering::Relaxed))
            .field("initiated", &self.0.initiated.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// A [`UdpTransportFactory`] that runs every datagram through Phobos.
///
/// It wraps any factory: gotatun's own sockets, or an embedder's. Every
/// datagram the device sends goes through [`PhobosCodec::wrap`] and every one
/// it receives through [`PhobosCodec::unwrap`], so the device only ever sees
/// WireGuard. The tunnel MTU must still be lowered by
/// [`Masking::overhead`](super::Masking::overhead).
///
/// # The rebind gate
///
/// A Phobos server drops everything except a handshake initiation from an
/// address that has not completed a handshake. After the device binds a new
/// socket (a new local address, as the server sees it), a transport message
/// sent before the initiation would only be dropped, and a keepalive would
/// not repair the path the way it does for plain WireGuard.
///
/// So every [`bind`](UdpTransportFactory::bind) starts a new *generation*,
/// and so does [`PhobosHandle::address_changed`], which an embedder must call
/// when the local address or path changes without a bind. The newest
/// socket's send half is in the newest generation; an older one stays in the
/// generation it was bound in, so an initiation it still sends cannot open
/// the gate for the new address. Until a handshake
/// initiation has been sent *successfully* on that generation, every other
/// WireGuard datagram on it is dropped (and reported as sent, which is what
/// the server would have done with it). The bind raises a "needs initiation"
/// request on the [`PhobosHandle`], and so do a failed initiation and a drop
/// while no initiation has been tried on the generation yet. The device polls
/// it from its timer loop and starts a handshake with every peer.
///
/// The gate opens only after the initiation's send returned `Ok`: while it is
/// pending, and after it failed, the generation still owes one.
///
/// # Control traffic
///
/// Under [`Masking::Stun`](super::Masking::Stun) and
/// [`Masking::Media`](super::Masking::Media), a task sends a STUN Binding
/// Request every [`PhobosCodec::control_interval`] to the address WireGuard
/// last sent to, but only while the newest handshake response this transport
/// saw (in either direction) is less than [`CONTROL_SESSION_WINDOW`] old.
/// The reference stops once the server drops an idle client, and a phone
/// should not power its radio for a tunnel nobody uses. The server's own
/// Binding Requests are answered from the receive half.
pub struct PhobosUdpFactory<F> {
    inner: F,
    shared: Arc<Shared>,
    /// The Binding Request period, if the masking has control traffic.
    control_interval: Option<Duration>,
}

impl<F> std::fmt::Debug for PhobosUdpFactory<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhobosUdpFactory").finish_non_exhaustive()
    }
}

impl<F: UdpTransportFactory> PhobosUdpFactory<F> {
    /// Wrap `inner` with the Phobos client for `cfg`.
    ///
    /// Returns the handle the device polls for handshake requests.
    ///
    /// # Errors
    ///
    /// Fails if `cfg` does not validate.
    pub fn new(inner: F, cfg: PhobosConfig) -> Result<(Self, PhobosHandle), ConfigError> {
        let codec = PhobosCodec::new(cfg)?;
        let control_interval = codec.control_interval();
        let shared = Arc::new(Shared {
            codec: Mutex::new(CodecState {
                codec,
                scratch: Vec::new(),
            }),
            generation: AtomicU64::new(0),
            initiated: AtomicU64::new(0),
            attempted: AtomicU64::new(0),
            bound: AtomicU64::new(0),
            needs_initiation: AtomicBool::new(false),
            last_handshake: Mutex::new(None),
            last_destination: Mutex::new(None),
        });
        let handle = PhobosHandle(Arc::clone(&shared));
        let factory = PhobosUdpFactory {
            inner,
            shared,
            control_interval,
        };
        Ok((factory, handle))
    }

    /// The wrapped factory.
    pub fn inner(&self) -> &F {
        &self.inner
    }

    /// The wrapped factory, mutably (e.g. to set socket options before bind).
    pub fn inner_mut(&mut self) -> &mut F {
        &mut self.inner
    }
}

impl<F: UdpTransportFactory> UdpTransportFactory for PhobosUdpFactory<F> {
    type Send = PhobosUdpSend<F::Send>;
    type Recv = PhobosUdpRecv<F::Recv, F::Send>;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let (tx, rx) = self.inner.bind(params).await?;
        let generation = self.shared.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.shared.bound.store(generation, Ordering::Release);
        self.shared.request_initiation();

        let send = PhobosUdpSend {
            inner: tx.clone(),
            shared: Arc::clone(&self.shared),
            bound_at: generation,
        };
        let control = self
            .control_interval
            .map(|interval| Task::spawn("phobos control", control_loop(send.clone(), interval)));
        let recv = PhobosUdpRecv {
            inner: rx,
            reply: tx,
            shared: Arc::clone(&self.shared),
            scratch: Vec::new(),
            _control: control,
        };
        Ok((send, recv))
    }
}

/// Send a Binding Request every `interval` on `send`'s socket. See
/// [`control_tick`]. Stopped by dropping the receive half that owns it.
async fn control_loop<S: UdpSend>(send: PhobosUdpSend<S>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        if control_tick(&send).await == ControlTick::Stop {
            return;
        }
    }
}

/// What one [`control_tick`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlTick {
    /// The socket is no longer the newest: the loop ends.
    Stop,
    /// Nothing to send: the gate is shut, the session is stale, or nothing
    /// has been sent yet.
    Skip,
    /// A Binding Request went out (or its send failed, which is only logged).
    Sent,
}

/// Send one Binding Request on `send`'s socket if it is the newest, its gate
/// is open and the newest handshake response is under
/// [`CONTROL_SESSION_WINDOW`] old.
async fn control_tick<S: UdpSend>(send: &PhobosUdpSend<S>) -> ControlTick {
    let shared = &send.shared;
    if !send.is_current() {
        return ControlTick::Stop;
    }
    if shared.gate_closed(send.generation()) || !shared.session_recent() {
        return ControlTick::Skip;
    }
    let Some(destination) = *shared.last_destination.lock() else {
        return ControlTick::Skip;
    };
    let request = shared.codec.lock().codec.binding_request();
    if let Err(e) = send
        .inner
        .send_to(Packet::copy_from(&request[..]), destination)
        .await
    {
        tracing::debug!("Phobos binding request send failed: {e}");
    }
    ControlTick::Sent
}

/// The send half of a [`PhobosUdpFactory`] socket.
#[derive(Clone)]
pub struct PhobosUdpSend<S> {
    inner: S,
    shared: Arc<Shared>,
    /// The generation the bind of this socket started.
    bound_at: u64,
}

impl<S> std::fmt::Debug for PhobosUdpSend<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhobosUdpSend")
            .field("bound_at", &self.bound_at)
            .finish_non_exhaustive()
    }
}

impl<S> PhobosUdpSend<S> {
    /// Whether this is the newest bound socket.
    fn is_current(&self) -> bool {
        self.shared.bound.load(Ordering::Acquire) == self.bound_at
    }

    /// The generation this socket's datagrams belong to: the shared one for
    /// the newest socket, so an address change gates it too, and its own
    /// bind's for an older one, so its initiations never open the gate for
    /// a newer address.
    fn generation(&self) -> u64 {
        if self.is_current() {
            self.shared.generation.load(Ordering::Acquire)
        } else {
            self.bound_at
        }
    }
}

impl<S: UdpSend> UdpSend for PhobosUdpSend<S> {
    type SendManyBuf = S::SendManyBuf;

    async fn send_to(&self, mut packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let initiation = has_type(&packet, HANDSHAKE_INITIATION);
        // Read once: an address change during this send starts a generation
        // this initiation was not sent for.
        let generation = self.generation();
        if !initiation && self.shared.gate_closed(generation) {
            tracing::trace!(
                "Phobos: dropping a {}-byte datagram until a handshake initiation \
                 has gone out on the new socket",
                packet.len()
            );
            if self.shared.attempted.load(Ordering::Acquire) < generation {
                self.shared.request_initiation();
            }
            return Ok(());
        }
        if has_type(&packet, HANDSHAKE_RESPONSE) {
            self.shared.saw_handshake();
        }
        *self.shared.last_destination.lock() = Some(destination);

        let preamble = {
            let mut state = self.shared.codec.lock();
            let CodecState { codec, scratch } = &mut *state;
            let preamble = codec.wrap(&packet, scratch).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Phobos cannot frame a {}-byte datagram: {e}", packet.len()),
                )
            })?;
            let buf = packet.buf_mut();
            buf.clear();
            buf.extend_from_slice(scratch);
            preamble
        };

        if let Some(request) = preamble
            && let Err(e) = self
                .inner
                .send_to(Packet::copy_from(&request[..]), destination)
                .await
        {
            // The datagram behind it meets the same path and reports for both.
            tracing::debug!("Phobos binding request send failed: {e}");
        }
        if initiation {
            // One is in flight for this generation: a request raised before
            // it (by the bind, or a drop) is answered, so the device does not
            // force a second one.
            self.shared
                .attempted
                .fetch_max(generation, Ordering::AcqRel);
            if self.shared.generation.load(Ordering::Acquire) == generation {
                self.shared.needs_initiation.store(false, Ordering::Release);
            }
        }
        let sent = self.inner.send_to(packet, destination).await;
        if initiation {
            if sent.is_ok() {
                self.shared
                    .initiated
                    .fetch_max(generation, Ordering::AcqRel);
            } else {
                self.shared.request_initiation();
            }
        }
        sent
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.inner.max_number_of_packets_to_send()
    }

    async fn send_many_to(
        &self,
        send_buf: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        // While the gate is shut, one at a time: an initiation opens it only
        // once its own send has succeeded.
        if self.shared.gate_closed(self.generation()) {
            for (packet, destination) in packets.drain(..) {
                self.send_to(packet, destination).await?;
            }
            return Ok(());
        }
        let mut wrapped = Vec::with_capacity(packets.len());
        {
            let mut state = self.shared.codec.lock();
            let CodecState { codec, scratch } = &mut *state;
            for (mut packet, destination) in packets.drain(..) {
                if has_type(&packet, HANDSHAKE_RESPONSE) {
                    self.shared.saw_handshake();
                }
                *self.shared.last_destination.lock() = Some(destination);
                match codec.wrap(&packet, scratch) {
                    Ok(preamble) => {
                        if let Some(request) = preamble {
                            wrapped.push((Packet::copy_from(&request[..]), destination));
                        }
                        let buf = packet.buf_mut();
                        buf.clear();
                        buf.extend_from_slice(scratch);
                        wrapped.push((packet, destination));
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Phobos cannot frame a {}-byte datagram: {e}",
                            packet.len()
                        );
                    }
                }
            }
        }
        // Preambles can push the batch past the inner sender's limit, so it
        // goes out in chunks of at most that many, in order. On failure,
        // whatever is left is dropped rather than handed back: it is already
        // wrapped, and a retry through here would wrap it again.
        let max = self.inner.max_number_of_packets_to_send().max(1);
        if wrapped.len() <= max {
            return self.inner.send_many_to(send_buf, &mut wrapped).await;
        }
        let mut rest = wrapped.into_iter();
        let mut chunk = Vec::with_capacity(max);
        loop {
            chunk.clear();
            chunk.extend(rest.by_ref().take(max));
            if chunk.is_empty() {
                return Ok(());
            }
            self.inner.send_many_to(send_buf, &mut chunk).await?;
        }
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        self.inner.set_fwmark(mark)
    }
}

/// The receive half of a [`PhobosUdpFactory`] socket. Owns the control task.
pub struct PhobosUdpRecv<R, S> {
    inner: R,
    /// The paired send half, unwrapped, for answering the server's Binding
    /// Requests.
    reply: S,
    shared: Arc<Shared>,
    scratch: Vec<(Packet, SocketAddr)>,
    _control: Option<Task>,
}

impl<R, S> std::fmt::Debug for PhobosUdpRecv<R, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhobosUdpRecv").finish_non_exhaustive()
    }
}

/// What one received datagram turned out to be.
enum Received {
    /// A WireGuard message, now the whole of the packet.
    WireGuard,
    /// A Binding Success to send back.
    Reply([u8; super::BINDING_SUCCESS_LEN]),
    Drop,
}

impl<R: UdpRecv, S: UdpSend> PhobosUdpRecv<R, S> {
    /// Unwrap `packet` in place, leaving only the WireGuard message in it.
    fn unwrap(&self, packet: &mut Packet, source: SocketAddr) -> Received {
        let buf = packet.buf_mut();
        let base = buf.as_ptr() as usize;
        let (start, len) = match self.shared.codec.lock().codec.unwrap(buf, source) {
            Unwrapped::WireGuard(message) => (message.as_ptr() as usize - base, message.len()),
            Unwrapped::Reply(reply) => return Received::Reply(reply),
            Unwrapped::Drop => return Received::Drop,
        };
        buf.advance(start);
        buf.truncate(len);
        if has_type(buf, HANDSHAKE_RESPONSE) {
            self.shared.saw_handshake();
        }
        Received::WireGuard
    }

    async fn send_reply(&self, reply: &[u8], destination: SocketAddr) {
        if let Err(e) = self
            .reply
            .send_to(Packet::copy_from(reply), destination)
            .await
        {
            tracing::debug!("Phobos binding response send failed: {e}");
        }
    }
}

impl<R: UdpRecv, S: UdpSend + 'static> UdpRecv for PhobosUdpRecv<R, S> {
    type RecvManyBuf = R::RecvManyBuf;

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        loop {
            let (mut packet, source) = self.inner.recv_from(pool).await?;
            match self.unwrap(&mut packet, source) {
                Received::WireGuard => return Ok((packet, source)),
                Received::Reply(reply) => self.send_reply(&reply, source).await,
                Received::Drop => {}
            }
        }
    }

    async fn recv_many_from(
        &mut self,
        recv_buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let start = packets.len();
        // Loop until something is delivered: control traffic alone is not a
        // receive as far as the caller is concerned.
        while packets.len() == start {
            self.scratch.clear();
            let mut fresh = std::mem::take(&mut self.scratch);
            self.inner
                .recv_many_from(recv_buf, pool, &mut fresh)
                .await?;
            for (mut packet, source) in fresh.drain(..) {
                match self.unwrap(&mut packet, source) {
                    Received::WireGuard => packets.push((packet, source)),
                    Received::Reply(reply) => self.send_reply(&reply, source).await,
                    Received::Drop => {}
                }
            }
            self.scratch = fresh;
        }
        Ok(())
    }

    fn enable_udp_gro(&self) -> io::Result<()> {
        self.inner.enable_udp_gro()
    }
}

/// An in-memory UDP network for tests: endpoints by address, a
/// [`UdpTransportFactory`] that binds a fresh local address every time, and
/// taps that see every datagram on the wire.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use parking_lot::Mutex;
    use tokio::sync::mpsc;

    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};

    /// One datagram on the wire: source, destination, bytes.
    pub(crate) type Wire = (SocketAddr, SocketAddr, Vec<u8>);
    type Inbox = mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>;

    #[derive(Default)]
    struct NetInner {
        routes: HashMap<SocketAddr, Inbox>,
        taps: Vec<mpsc::UnboundedSender<Wire>>,
        /// Fail every send, as a socket whose route is gone does.
        failing: bool,
    }

    /// The network. Datagrams to an address nobody is attached to vanish.
    #[derive(Clone, Default)]
    pub(crate) struct Net(Arc<Mutex<NetInner>>);

    impl Net {
        /// Every datagram sent from now on.
        pub(crate) fn tap(&self) -> mpsc::UnboundedReceiver<Wire> {
            let (tx, rx) = mpsc::unbounded_channel();
            self.0.lock().taps.push(tx);
            rx
        }

        /// Receive what is sent to `addr`.
        pub(crate) fn attach(&self, addr: SocketAddr) -> Endpoint {
            let (tx, rx) = mpsc::unbounded_channel();
            self.0.lock().routes.insert(addr, tx);
            Endpoint {
                net: self.clone(),
                addr,
                rx,
            }
        }

        /// Make every send fail, or work again.
        pub(crate) fn set_failing(&self, failing: bool) {
            self.0.lock().failing = failing;
        }

        fn deliver(&self, source: SocketAddr, destination: SocketAddr, bytes: &[u8]) {
            let mut inner = self.0.lock();
            inner
                .taps
                .retain(|tap| tap.send((source, destination, bytes.to_vec())).is_ok());
            if let Some(route) = inner.routes.get(&destination) {
                let _ = route.send((bytes.to_vec(), source));
            }
        }
    }

    /// One attached address. Detaches on drop.
    pub(crate) struct Endpoint {
        net: Net,
        pub(crate) addr: SocketAddr,
        rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    }

    impl Endpoint {
        pub(crate) fn send(&self, bytes: &[u8], destination: SocketAddr) {
            self.net.deliver(self.addr, destination, bytes);
        }

        pub(crate) async fn recv(&mut self) -> (Vec<u8>, SocketAddr) {
            self.rx
                .recv()
                .await
                .expect("the net outlives its endpoints")
        }
    }

    impl Drop for Endpoint {
        fn drop(&mut self) {
            self.net.0.lock().routes.remove(&self.addr);
        }
    }

    /// Binds `ip` with a new port on every call, as a rebind behind a NAT
    /// or onto another network would look to the server.
    pub(crate) struct PipeFactory {
        net: Net,
        ip: IpAddr,
        next_port: u16,
        batch_limit: usize,
    }

    impl PipeFactory {
        pub(crate) fn new(net: Net, ip: IpAddr, first_port: u16) -> Self {
            PipeFactory {
                net,
                ip,
                next_port: first_port,
                batch_limit: 1,
            }
        }

        /// Accept batches of up to `limit` in `send_many_to`, and refuse
        /// larger ones as a real socket does.
        pub(crate) fn with_batch_limit(mut self, limit: usize) -> Self {
            self.batch_limit = limit;
            self
        }
    }

    impl UdpTransportFactory for PipeFactory {
        type Send = PipeSend;
        type Recv = PipeRecv;

        async fn bind(
            &mut self,
            _params: &UdpTransportFactoryParams,
        ) -> io::Result<(PipeSend, PipeRecv)> {
            let addr = SocketAddr::new(self.ip, self.next_port);
            self.next_port += 1;
            let endpoint = self.net.attach(addr);
            Ok((
                PipeSend {
                    net: self.net.clone(),
                    addr,
                    batch_limit: self.batch_limit,
                },
                PipeRecv(endpoint),
            ))
        }
    }

    #[derive(Clone)]
    pub(crate) struct PipeSend {
        net: Net,
        addr: SocketAddr,
        batch_limit: usize,
    }

    impl UdpSend for PipeSend {
        type SendManyBuf = ();

        async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
            if self.net.0.lock().failing {
                return Err(io::ErrorKind::NetworkUnreachable.into());
            }
            self.net.deliver(self.addr, destination, &packet);
            Ok(())
        }

        fn max_number_of_packets_to_send(&self) -> usize {
            self.batch_limit
        }

        async fn send_many_to(
            &self,
            _buf: &mut (),
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> io::Result<()> {
            if packets.len() > self.batch_limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{} packets over the limit {}",
                        packets.len(),
                        self.batch_limit
                    ),
                ));
            }
            for (packet, destination) in packets.drain(..) {
                self.send_to(packet, destination).await?;
            }
            Ok(())
        }

        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(Some(self.addr))
        }
    }

    pub(crate) struct PipeRecv(Endpoint);

    impl UdpRecv for PipeRecv {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let (bytes, source) = self.0.recv().await;
            Ok((Packet::copy_from(&bytes[..]), source))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use tokio::sync::mpsc::UnboundedReceiver;

    use super::testing::{Net, PipeFactory, Wire};
    use super::*;
    use crate::phobos::Masking;

    fn server() -> SocketAddr {
        "10.0.0.9:7000".parse().unwrap()
    }

    fn client_ip() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    fn config(masking: Masking) -> PhobosConfig {
        let mut cfg = PhobosConfig::new(b"synthetic-preset-key".to_vec()).unwrap();
        cfg.masking = masking;
        cfg
    }

    fn params() -> UdpTransportFactoryParams {
        UdpTransportFactoryParams {
            addr: None,
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        }
    }

    fn message(msg_type: u8, len: usize) -> Vec<u8> {
        let mut m = vec![0x5a; len];
        m[..4].copy_from_slice(&[msg_type, 0, 0, 0]);
        m
    }

    fn wg(msg_type: u8, len: usize) -> Packet {
        Packet::copy_from(&message(msg_type, len)[..])
    }

    fn factory_on(net: &Net, masking: Masking) -> (PhobosUdpFactory<PipeFactory>, PhobosHandle) {
        let pipe = PipeFactory::new(net.clone(), client_ip(), 40000);
        PhobosUdpFactory::new(pipe, config(masking)).unwrap()
    }

    /// What a server sees in one datagram.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        /// A WireGuard message of this type.
        Wg(u8),
        /// A STUN Binding Request.
        BindingRequest,
        /// Anything else.
        Other,
    }

    /// Everything on the wire so far, as the server reads it.
    fn read_wire(
        tap: &mut UnboundedReceiver<Wire>,
        server: &mut PhobosCodec,
    ) -> Vec<(SocketAddr, Seen)> {
        let mut seen = Vec::new();
        while let Ok((source, _, mut bytes)) = tap.try_recv() {
            let what = match server.unwrap(&mut bytes, source) {
                Unwrapped::WireGuard(m) => Seen::Wg(m[0]),
                Unwrapped::Reply(_) => Seen::BindingRequest,
                Unwrapped::Drop => Seen::Other,
            };
            seen.push((source, what));
        }
        seen
    }

    fn server_codec(masking: Masking) -> PhobosCodec {
        PhobosCodec::new(config(masking)).unwrap()
    }

    /// After a rebind, nothing leaves the new socket before an initiation,
    /// and the transport keeps asking for one until it has gone out.
    #[tokio::test]
    async fn rebind_gates_until_initiation() {
        let net = Net::default();
        let mut tap = net.tap();
        let mut srv = server_codec(Masking::Stun);
        let (mut factory, handle) = factory_on(&net, Masking::Stun);

        let (tx1, rx1) = factory.bind(&params()).await.unwrap();
        let first = tx1.local_addr().unwrap().unwrap();
        assert!(handle.take_initiation_request(), "a bind asks for one");
        assert!(!handle.take_initiation_request(), "taken once");

        tx1.send_to(wg(4, 64), server()).await.unwrap();
        assert!(
            handle.take_initiation_request(),
            "a held-back datagram asks again"
        );
        assert_eq!(read_wire(&mut tap, &mut srv), []);

        tx1.send_to(wg(1, 148), server()).await.unwrap();
        tx1.send_to(wg(4, 64), server()).await.unwrap();
        assert_eq!(
            read_wire(&mut tap, &mut srv),
            [
                (first, Seen::BindingRequest),
                (first, Seen::Wg(1)),
                (first, Seen::Wg(4)),
            ]
        );
        assert!(!handle.take_initiation_request());

        // Rebind onto a new local address.
        drop(rx1);
        let (tx2, _rx2) = factory.bind(&params()).await.unwrap();
        let second = tx2.local_addr().unwrap().unwrap();
        assert_ne!(first, second);
        assert!(handle.take_initiation_request());

        tx2.send_to(wg(4, 64), server()).await.unwrap();
        tx2.send_to(wg(3, 64), server()).await.unwrap();
        assert!(handle.take_initiation_request());
        assert_eq!(read_wire(&mut tap, &mut srv), [], "held back");

        // An initiation the old socket still sends opens nothing on the new.
        tx1.send_to(wg(1, 148), server()).await.unwrap();
        assert_eq!(
            read_wire(&mut tap, &mut srv).len(),
            2,
            "old socket: request, init"
        );
        tx2.send_to(wg(4, 64), server()).await.unwrap();
        assert_eq!(read_wire(&mut tap, &mut srv), [], "still held back");
        let _ = handle.take_initiation_request();

        tx2.send_to(wg(1, 148), server()).await.unwrap();
        tx2.send_to(wg(4, 64), server()).await.unwrap();
        assert_eq!(
            read_wire(&mut tap, &mut srv),
            [
                (second, Seen::BindingRequest),
                (second, Seen::Wg(1)),
                (second, Seen::Wg(4)),
            ],
            "the initiation is the first WireGuard message from the new address"
        );
        assert!(!handle.take_initiation_request());
    }

    /// An initiation that fails to go out leaves the gate shut.
    #[tokio::test]
    async fn a_failed_initiation_keeps_the_gate_shut() {
        let net = Net::default();
        let mut tap = net.tap();
        let mut srv = server_codec(Masking::Stun);
        let (mut factory, handle) = factory_on(&net, Masking::Stun);
        let (tx, _rx) = factory.bind(&params()).await.unwrap();
        assert!(handle.take_initiation_request());

        // Too long for a STUN DATA attribute: the wrap, and so the send, fails.
        let err = tx.send_to(wg(1, 70_000), server()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        tx.send_to(wg(4, 64), server()).await.unwrap();
        assert!(handle.take_initiation_request(), "still gated");

        // The socket itself fails the send.
        net.set_failing(true);
        let err = tx.send_to(wg(1, 148), server()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NetworkUnreachable);
        net.set_failing(false);
        assert!(handle.take_initiation_request(), "the failure asks again");
        tx.send_to(wg(4, 64), server()).await.unwrap();
        assert_eq!(read_wire(&mut tap, &mut srv), [], "still gated");
        // That drop came after an attempt, whose failure already asked: the
        // device is not asked twice for one lost initiation.
        assert!(!handle.take_initiation_request());

        tx.send_to(wg(1, 148), server()).await.unwrap();
        tx.send_to(wg(4, 64), server()).await.unwrap();
        let me = tx.local_addr().unwrap().unwrap();
        assert_eq!(
            read_wire(&mut tap, &mut srv),
            [
                (me, Seen::BindingRequest),
                (me, Seen::Wg(1)),
                (me, Seen::Wg(4))
            ]
        );
    }

    /// The batched path gates the same way and keeps the wire order.
    #[tokio::test]
    async fn send_many_gates_like_send() {
        let net = Net::default();
        let mut tap = net.tap();
        let mut srv = server_codec(Masking::Stun);
        let (mut factory, _handle) = factory_on(&net, Masking::Stun);
        let (tx, _rx) = factory.bind(&params()).await.unwrap();
        let me = tx.local_addr().unwrap().unwrap();

        let mut batch = vec![
            (wg(4, 64), server()),
            (wg(1, 148), server()),
            (wg(4, 64), server()),
        ];
        tx.send_many_to(&mut (), &mut batch).await.unwrap();
        assert!(batch.is_empty());
        let mut batch = vec![(wg(4, 80), server()), (wg(1, 148), server())];
        tx.send_many_to(&mut (), &mut batch).await.unwrap();
        assert_eq!(
            read_wire(&mut tap, &mut srv),
            [
                (me, Seen::BindingRequest),
                (me, Seen::Wg(1)),
                (me, Seen::Wg(4)),
                (me, Seen::Wg(4)),
                (me, Seen::BindingRequest),
                (me, Seen::Wg(1)),
            ]
        );
    }

    /// A batch that preambles push past the inner sender's limit goes out in
    /// chunks, in order, instead of failing whole.
    #[tokio::test]
    async fn send_many_respects_the_inner_batch_limit() {
        let net = Net::default();
        let mut tap = net.tap();
        let mut srv = server_codec(Masking::Stun);
        let pipe = PipeFactory::new(net.clone(), client_ip(), 40000).with_batch_limit(2);
        let (mut factory, _handle) = PhobosUdpFactory::new(pipe, config(Masking::Stun)).unwrap();
        let (tx, _rx) = factory.bind(&params()).await.unwrap();
        let me = tx.local_addr().unwrap().unwrap();
        assert_eq!(tx.max_number_of_packets_to_send(), 2);

        tx.send_to(wg(1, 148), server()).await.unwrap();
        let _ = read_wire(&mut tap, &mut srv);

        // Two in, three out: the initiation brings its Binding Request.
        let mut batch = vec![(wg(4, 64), server()), (wg(1, 148), server())];
        tx.send_many_to(&mut (), &mut batch).await.unwrap();
        assert_eq!(
            read_wire(&mut tap, &mut srv),
            [
                (me, Seen::Wg(4)),
                (me, Seen::BindingRequest),
                (me, Seen::Wg(1)),
            ]
        );
    }

    /// An address change without a bind closes the current socket's gate
    /// and asks for an initiation, like a rebind.
    #[tokio::test]
    async fn address_change_gates_until_initiation() {
        let net = Net::default();
        let mut tap = net.tap();
        let mut srv = server_codec(Masking::Stun);
        let (mut factory, handle) = factory_on(&net, Masking::Stun);
        let (tx, _rx) = factory.bind(&params()).await.unwrap();
        let me = tx.local_addr().unwrap().unwrap();
        tx.send_to(wg(1, 148), server()).await.unwrap();
        tx.send_to(wg(4, 64), server()).await.unwrap();
        assert_eq!(read_wire(&mut tap, &mut srv).len(), 3);
        assert!(!handle.take_initiation_request());

        handle.address_changed();
        assert!(handle.take_initiation_request());
        tx.send_to(wg(4, 64), server()).await.unwrap();
        let mut batch = vec![(wg(4, 64), server())];
        tx.send_many_to(&mut (), &mut batch).await.unwrap();
        assert_eq!(read_wire(&mut tap, &mut srv), [], "held back");
        assert!(handle.take_initiation_request(), "no initiation tried yet");

        tx.send_to(wg(1, 148), server()).await.unwrap();
        tx.send_to(wg(4, 64), server()).await.unwrap();
        assert_eq!(
            read_wire(&mut tap, &mut srv),
            [
                (me, Seen::BindingRequest),
                (me, Seen::Wg(1)),
                (me, Seen::Wg(4)),
            ]
        );
    }

    /// An initiation answers a pending request: the device is not asked to
    /// force another, and drops after it do not ask again.
    #[tokio::test]
    async fn an_initiation_answers_the_request() {
        let (mut factory, handle) = factory_on(&Net::default(), Masking::Stun);
        let (tx, _rx) = factory.bind(&params()).await.unwrap();
        // Not taken: the tunnel sends its own initiation first.
        tx.send_to(wg(4, 64), server()).await.unwrap();
        tx.send_to(wg(1, 148), server()).await.unwrap();
        assert!(!handle.take_initiation_request());

        handle.address_changed();
        tx.send_to(wg(1, 148), server()).await.unwrap();
        assert!(!handle.take_initiation_request());
    }

    /// Under every masking, what the server wraps arrives as WireGuard, its
    /// Binding Request is answered on the wire and never delivered.
    #[tokio::test]
    async fn receive_unwraps_and_answers_binding_requests() {
        for masking in [Masking::None, Masking::Stun, Masking::Media] {
            for batched in [false, true] {
                let net = Net::default();
                let mut tap = net.tap();
                let srv_ep = net.attach(server());
                let mut srv = server_codec(masking);
                let (mut factory, _handle) = factory_on(&net, masking);
                let (tx, mut rx) = factory.bind(&params()).await.unwrap();
                let me = tx.local_addr().unwrap().unwrap();

                if masking != Masking::None {
                    srv_ep.send(&srv.binding_request(), me);
                }
                // Plain WireGuard from the network is never delivered.
                srv_ep.send(&message(4, 64), me);
                let response = message(2, 92);
                let mut out = Vec::new();
                let _ = srv.wrap(&response, &mut out).unwrap();
                srv_ep.send(&out, me);

                let mut pool = PacketBufPool::new(4);
                let (packet, source) = if batched {
                    let mut got = Vec::new();
                    rx.recv_many_from(&mut (), &mut pool, &mut got)
                        .await
                        .unwrap();
                    assert_eq!(got.len(), 1, "{masking:?}");
                    got.pop().unwrap()
                } else {
                    rx.recv_from(&mut pool).await.unwrap()
                };
                assert_eq!(source, server());
                assert_eq!(&packet[..], &response[..], "{masking:?}");

                let wire: Vec<_> = std::iter::from_fn(|| tap.try_recv().ok())
                    .filter(|(source, _, _)| *source == me)
                    .collect();
                if masking == Masking::None {
                    assert!(wire.is_empty());
                } else {
                    let [(_, dst, success)] = &wire[..] else {
                        panic!("{masking:?}: expected one Binding Success, got {wire:?}");
                    };
                    assert_eq!(*dst, server());
                    assert_eq!(success.len(), super::super::BINDING_SUCCESS_LEN);
                    assert_eq!(success[..2], [0x01, 0x01], "Binding Success");
                }
            }
        }
    }

    /// The periodic Binding Request runs only while the newest handshake
    /// response is under 180 s old, and only on the newest socket. Driven
    /// tick by tick on the mock clock.
    #[cfg(feature = "mock_instant")]
    #[tokio::test]
    async fn binding_request_stops_after_180s_without_handshake() {
        use mock_instant::thread_local::MockClock;

        let net = Net::default();
        let mut tap = net.tap();
        let srv_ep = net.attach(server());
        let mut srv = server_codec(Masking::Stun);
        let (mut factory, handle) = factory_on(&net, Masking::Stun);
        let (tx, mut rx) = factory.bind(&params()).await.unwrap();
        let me = tx.local_addr().unwrap().unwrap();

        let mut tick = async |tx: &PhobosUdpSend<_>, tap: &mut UnboundedReceiver<Wire>| {
            let _ = read_wire(tap, &mut srv);
            let step = control_tick(tx).await;
            let seen = read_wire(tap, &mut srv);
            match step {
                ControlTick::Sent => assert_eq!(seen, [(me, Seen::BindingRequest)]),
                _ => assert_eq!(seen, []),
            }
            step
        };

        assert_eq!(tick(&tx, &mut tap).await, ControlTick::Skip, "gate shut");
        tx.send_to(wg(1, 148), server()).await.unwrap();
        assert_eq!(
            tick(&tx, &mut tap).await,
            ControlTick::Skip,
            "no handshake yet"
        );

        // The server's response arrives.
        let mut out = Vec::new();
        let _ = server_codec(Masking::Stun)
            .wrap(&message(2, 92), &mut out)
            .unwrap();
        srv_ep.send(&out, me);
        let (packet, _) = rx.recv_from(&mut PacketBufPool::new(1)).await.unwrap();
        assert_eq!(packet[0], 2);
        assert_eq!(tick(&tx, &mut tap).await, ControlTick::Sent, "session up");

        MockClock::advance(Duration::from_secs(179));
        assert_eq!(tick(&tx, &mut tap).await, ControlTick::Sent, "179 s on");

        MockClock::advance(Duration::from_secs(1));
        assert_eq!(
            tick(&tx, &mut tap).await,
            ControlTick::Skip,
            "stopped at 180 s"
        );

        // A response we send counts too: a server-initiated handshake.
        tx.send_to(wg(2, 92), server()).await.unwrap();
        assert_eq!(tick(&tx, &mut tap).await, ControlTick::Sent, "restarted");

        // An address change shuts the gate, and with it the control traffic.
        handle.address_changed();
        assert_eq!(
            tick(&tx, &mut tap).await,
            ControlTick::Skip,
            "address changed"
        );
        tx.send_to(wg(1, 148), server()).await.unwrap();
        assert_eq!(tick(&tx, &mut tap).await, ControlTick::Sent);

        // A rebind ends the old socket's loop.
        let (tx2, _rx2) = factory.bind(&params()).await.unwrap();
        assert_eq!(tick(&tx, &mut tap).await, ControlTick::Stop, "old socket");
        assert_eq!(
            tick(&tx2, &mut tap).await,
            ControlTick::Skip,
            "new socket gated"
        );
    }
}
