# libssh-rs

Bindings to [libssh](https://www.libssh.org/).

This repo is home to the `libssh-rs-sys` crate, which provides FFI bindings to `libssh`.

## Features

The `vendored` feature causes a static version of libssh to be compiled and linked into your program.

The `vendored-openssl` feature causes a vendored copy of `openssl` to be compiled and linked into your program.

## License

This crate is licensed under the MIT license.

Note that the `vendored` directory is a submodule that references `libssh`;
`libssh` is itself [GNU Library (or: Lesser) General Public License
(LGPL)](http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html) which has a
viral clause in the case where you modify `libssh`.  The license is explained
[on the libssh features page](https://www.libssh.org/features/); the summary
is that using an unmodified `libssh-rs-sys` crate will not trigger a viral clause,
and you can use this crate under the terms of the MIT license.

