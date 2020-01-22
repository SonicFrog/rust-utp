//! Implementation of the [Micro Transport Protocol][spec].
//!
//! This library provides both a socket interface (`UtpSocket`) and a stream
//! interface (`UtpStream`).
//! I recommend that you use `UtpStream`, as it implements the `Read` and
//! `Write` traits we all know (and love) from `std::io`, which makes it
//! generally easier to work with than `UtpSocket`.
//!
//! [spec]: http://www.bittorrent.org/beps/bep_0029.html
//!
//! # Installation
//!
//! Ensure your `Cargo.toml` contains:
//!
//! ```toml
//! [dependencies]
//! utp = "*"
//! ```
#![deny(missing_docs)]
// Optional features
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(
    feature = "clippy",
    allow(
        len_without_is_empty,
        doc_markdown,
        needless_return,
        cast_ptr_alignment,
    )
)]

#[macro_use]
extern crate log;

// Public API
pub use socket::UtpSocketRef as UtpSocket;
pub use socket::UtpStream;
pub use socket::UtpStreamDriver;

mod bit_iterator;
mod error;
mod packet;
mod socket;
mod time;
mod util;
