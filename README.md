# rust-utp

A [Micro Transport Protocol](http://www.bittorrent.org/beps/bep_0029.html) library implemented in Rust.

The current implementation is somewhat incomplete, lacking both congestion
control and full packet loss handling (though some cases are handled). However,
it does support the Selective Acknowledgment extension, handles unordered and
duplicate packets and presents a stream interface (`UtpStream`).

![Build status](https://api.travis-ci.org/meqif/rust-utp.svg)

## Building

`cargo build --release`

Note that non-release builds are *much* slower.

## To implement

- [ ] congestion control
- [ ] proper connection closing
    - [x] handle both RST and FIN
    - [x] send FIN on close
    - [ ] automatically send FIN (or should it be RST?) on `drop` if not already closed
- [x] sending RST on mismatch
- [ ] setters and getters that hide header field endianness conversion
- [x] SACK extension
- [ ] handle packet loss
    - [x] send triple-ACK to re-request lost packet (fast resend request)
    - [x] rewind send window and resend in reply to triple-ACK (fast resend)
    - [ ] resend packet on ACK timeout
- [x] stream interface
- [x] handle unordered packets
- [ ] path MTU discovery
- [x] duplicate packet handling

## License

This library is distributed under similar terms to Rust: dual licensed under the MIT license and the Apache license (version 2.0).

See LICENSE-APACHE, LICENSE-MIT, and COPYRIGHT for details.
