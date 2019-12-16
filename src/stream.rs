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
    close_fut: Pin<Box<dyn Future<Output = Result<()>>>>,
    write_fut: Option<Pin<Box<dyn Future<Output = Result<usize>>>>>,
    flush_fut: Option<Pin<Box<dyn Future<Output = Result<()>>>>>,
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
        Self {
            socket,
            flush_fut: None,
            close_fut: Box::pin(socket.close()),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.socket.peer_addr()
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

impl AsyncWrite for UtpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize>> {
        if let Some(mut f) = self.write_fut {
            // already in the process of writing
            f.as_mut().poll(cx)
        } else {
            let mut future = Box::pin(self.socket.send_to(buf));

            if let Poll::Ready(Ok(written)) = future.as_mut().poll(cx) {
                Poll::Ready(Ok(written))
            } else {
                self.write_fut = Some(future);
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        match self.as_mut().flush_fut {
            Some(ref mut v) => v.as_mut().poll(cx),
            None => {
                let mut future = Box::pin(self.socket.flush());

                if let Poll::Ready(e) = future.as_mut().poll(cx) {
                    Poll::Ready(e)
                } else {
                    self.flush_fut = Some(future);
                    Poll::Pending
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        self.close_fut.as_mut().poll(cx)
    }
}
