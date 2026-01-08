# stack_sanitizer

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache 2.0/MIT Licensed][license-image]
![MSRV][rustc-image]
[![Build Status][build-image]][build-link]

Securely zero/sanitize the stack while avoiding compiler optimizations.

This crate implements a portable approach to securely zeroing the stack using
techniques which guarantee they won't be "optimized away" by the compiler.

[Documentation]

## About

[Zeroing memory securely is hard] - compilers optimize for performance, and
in doing so they love to "optimize away" unnecessary zeroing calls, as well 
as make extra copies of data on the stack that cannot be easily zeroed. That's 
what this crate is for.

This crate is about tricks: it uses [psm::on_stack] to run a closure on 
a portable stack, and then uses [zeroize] to zero that stack. `psm` implements
all of the assembly for several different architectures, and the [zeroize]
portion of the task was implemented in pure Rust.

- No functionality besides securely zeroing the a function's stack usage!

## License

Licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[build-image]: https://github.com/RustCrypto/utils/actions/workflows/zeroize.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/utils/actions/workflows/zeroize.yml?query=branch:master

[//]: # (general links)

[zeroize]: https://en.wikipedia.org/wiki/Zeroisation
[Zeroing memory securely is hard]: http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
[psm::on_stack]: https://docs.rs/psm/latest/psm/fn.on_stack.html
[good cryptographic hygiene]: https://github.com/veorq/cryptocoding#clean-memory-of-secret-data
