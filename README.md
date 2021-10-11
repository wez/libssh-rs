# libssh-rs

Bindings to [libssh](https://www.libssh.org/).

This repo is home to the `libssh-rs-sys` crate, which provides FFI bindings to `libssh`.

## Features

The `vendored` feature causes a static version of libssh to be compiled and linked into your program.
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

