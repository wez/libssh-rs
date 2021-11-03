# libssh-rs-sys

[![Build Status](https://github.com/wez/libssh-rs/workflows/Linux/badge.svg)](https://github.com/wez/libssh-rs/actions?workflow=Linux)
[![Build Status](https://github.com/wez/libssh-rs/workflows/Windows/badge.svg)](https://github.com/wez/libssh-rs/actions?workflow=Windows)
[![Build Status](https://github.com/wez/libssh-rs/workflows/macOS/badge.svg)](https://github.com/wez/libssh-rs/actions?workflow=macOS)

Native bindings to [libssh](https://www.libssh.org/).

## Features

The `vendored` feature causes a static version of libssh to be compiled and linked into your program.
If no system `libssh` is detected at build time, or that system library is too old, then the vendored
`libssh` implementation will be used automatically. Note that the `libssh-rs` bindings make use of
a couple of new interfaces that have not made it into a released version of `libssh` at the time
of writing this note, so all users will be effectively running with `vendored` enabled until libssh
releases version `0.9.7`.

The `vendored-openssl` feature causes a vendored copy of `openssl` to be compiled and linked into your program.

On macOS and Windows systems, you most likely want to enable both `vendored` and `vendored-openssl`.

## License

This crate is licensed under the MIT license, and is:
Copyright (c) 2021-Present Wez Furlong.

Note that the `vendored` directory is a submodule that references `libssh`;
`libssh` is itself [GNU Library (or: Lesser) General Public License
(LGPL)](http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html) which has a
viral clause in the case where you modify `libssh`.  The license is explained
[on the libssh features page](https://www.libssh.org/features/); the summary is
that simply using an unmodified `libssh-rs-sys` crate will not trigger that
viral clause, and you are thus able to use this crate under the terms of the
MIT license.

