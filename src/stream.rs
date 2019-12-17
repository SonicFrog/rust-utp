use std::future::Future;
use std::io::Result;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::UtpSocket;

use tokio::io::{AsyncRead, AsyncWrite};

/// A structure that represents a uTP (Micro Transport Protocol) stream between
/// a local socket and a remote socket.
///
/// The connection will be closed when the value is dropped (either explicitly
/// or when it goes out of scope).
///
/// The default maximum retransmission retries is 5, which translates to about
/// 16 seconds. It can be changed by calling `set_max_retransmission_retries`.
/// Notice that the initial congestion timeout is 500 ms and doubles with each
/// timeout.
pub struct UtpStream {
    socket: UtpSocket,
}

impl UtpStream {
    /// Creates a new `UtpStream` listening on the given address
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = UtpSocket::bind(addr).await?;

        Ok(Self::from_raw_parts(socket))
    }

    /// Create a new `UtpStream` that connects to the given address
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let socket = UtpSocket::connect(addr).await?;

        Ok(Self::from_raw_parts(socket))
    }

    fn from_raw_parts(socket: UtpSocket) -> Self {
        Self { socket }
    }

    /// Returns the local address to which this `UtpStream` is bound
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns the remote address to which this `UtpStream` is connected
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.socket.peer_addr()
    }

    /// Close this `UtpStream` and flushes all pending packets
    pub async fn close(&mut self) -> Result<()> {
        self.socket.close().await
    }
}

impl AsyncRead for UtpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        let mut future = self.socket.recv_from(buf);

        unsafe { Pin::new_unchecked(&mut future) }
            .poll(cx)
            .map(|r| match r {
                Ok((r, _)) => Ok(r),
                Err(e) => Err(e),
            })
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
        let mut future = self.socket.send_to(buf);

        unsafe { Pin::new_unchecked(&mut future) }.poll(cx)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<()>> {
        let mut future = self.socket.flush();

        unsafe { Pin::new_unchecked(&mut future) }.poll(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<()>> {
        let mut future = self.socket.close();

        unsafe { Pin::new_unchecked(&mut future) }.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU16, Ordering};

    use super::*;
    use crate::UtpSocket;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, ErrorKind};
    use tokio::task;

    const ADDR: &str = "127.0.0.1";
    static PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

    fn next_test_ip4() -> (Ipv4Addr, u16) {
        (
            ADDR.parse().unwrap(),
            PORT_OFFSET.fetch_add(1, Ordering::Relaxed) + 9000,
        )
    }

    fn next_test_addr() -> SocketAddr {
        next_test_ip4().into()
    }

    #[tokio::test]
    async fn async_write() {
        let addr = next_test_addr();

        let mut client = UtpSocket::bind(addr).await.expect("failed to bind");

        task::spawn(async move {
            let mut stream =
                UtpStream::connect(addr).await.expect("failed to connect");
            let buf = [0u8; 256];

            stream.write(&buf).await.expect("failed to send");

            stream.close().await.expect("failed to flush");
        });

        let mut buf = [1u8; 1024];

        let (read, _) =
            client.recv_from(&mut buf).await.expect("failed to receive");

        assert_eq!(read, 256usize, "read incorrect amount of bytes");

        client.close().await.expect("failed to close stream");
    }

    #[tokio::test]
    async fn async_read() {
        let addr = next_test_addr();

        task::spawn(async move {
            let mut client =
                UtpSocket::connect(addr).await.expect("failed to bind");
            let buf = [0u8; 256];
            let read = client.send_to(&buf).await.expect("failed to send_to");

            assert_eq!(read, 256, "read wrong amount of bytes");

            client.close().await.expect("failed to close");
        });

        let mut buf = [1u8; 1024];
        let mut stream =
            UtpStream::bind(addr).await.expect("failed to connect");

        stream.read(&mut buf).await.expect("failed to read");
        stream.close().await.expect("failed to close");
    }

    #[tokio::test]
    async fn async_read_exact_too_much() {
        let addr = next_test_addr();

        task::spawn(async move {
            let buf = [1u8; 512];
            let mut client =
                UtpSocket::connect(addr).await.expect("failed to bind");

            client.send_to(&buf).await.expect("failed to write");
            client.close().await.expect("failed to close");
        });

        let mut buf = [0u8; 1024];
        let mut stream = UtpStream::bind(addr).await.expect("failed to bind");

        let err = stream
            .read_exact(&mut buf)
            .await
            .expect_err("did not encounter timeout");

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof, "error kind is wrong");
    }

    #[tokio::test]
    async fn async_read_exact() {
        let addr = next_test_addr();

        task::spawn(async move {
            let buf = [1u8; 256];
            let mut client =
                UtpSocket::connect(addr).await.expect("failed to bind");

            for _ in 0..4 {
                client.send_to(&buf).await.expect("failed to write");
            }

            client.close().await.expect("failed to close");
        });

        let mut buf = [0u8; 1024];
        let mut stream = UtpStream::bind(addr).await.expect("failed to bind");

        stream
            .read_exact(&mut buf)
            .await
            .expect("did not succesfully received the data");
    }
}
