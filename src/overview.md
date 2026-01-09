# Overview

Owl is a programming language and proof assistant designed to help developers build cryptographic security protocols with mathematical guarantees of correctness and security. 

The intended workflow of Owl is as follows: first, the developer writes a protocol in the [Owl language](./example.md), which uses information-flow and refinement types to specify and prove security. Then, the protocol can be extracted using our [compiler](./compiler.md) into a high-performance implementation in [Verus](https://verus-lang.github.io/verus/guide/), an extension of Rust with formal verification capabilities, that is guaranteed by construction to be functionally correct and secure against source-level side channels. 

### Owl's Design

The Owl language is backed by two main programming language technologies: [_information-flow types_](https://www.cs.cornell.edu/andru/papers/jsac/sm-jsac03.pdf), which reasons about the secrecy information of data in the program; and [_refinement types_](https://arxiv.org/abs/2010.07763), which use SMT solvers (we use [Z3](https://github.com/Z3Prover/z3)) to imbue types with logical specifications.  

The key novelty of Owl is that information-flow and refinement types, on their own, are not enough. We also need to faithfully model the security guarantees of cryptographic operations, such as [encryption](./aenc.md). To do this, Owl's type system comes with a [soundness proof](https://eprint.iacr.org/2023/473.pdf) that _every well-typed protocol is cryptographically secure_. 

In addition to formal verification of protocol _designs_, Owl also enables protocol developers to automatically extract real-world code that one can link with. Our compiler, described in our [USENIX Security paper](https://eprint.iacr.org/2025/1092), uses Verus to compile Owl protocols into efficient, interoperable, side-channel resistant Rust libraries that are automatically formally verified to be correct. 


#### Comparisons between Owl and Other Tools

There are two classes of verification tools which Owl intersects with: game-hopping cryptographic provers, based on relational program logics, such as [EasyCrypt](https://www.easycrypt.info); and "security protocol verifiers", such as [CryptoVerif](https://cryptoverif.inria.fr) and [Tamarin](https://tamarin-prover.com).

Compared to EasyCrypt, Owl is less general but significantly more automated. EasyCrypt allows the user to prove arbitrary cryptographic theorems using an expressive probabilistic logic; on the other hand, Owl is specifically targeted at security protocols, such as [WireGuard](https://wireguard.com) [HPKE](https://datatracker.ietf.org/doc/rfc9180/).  

Compared to CryptoVerif and Tamarin, the advantage of Owl is that its type system guarantees the properties of [_computational security_](https://www.cs.princeton.edu/courses/archive/fall07/cos433/lec3.pdf), _compositionality_, and a high degree of _proof automation_. 

