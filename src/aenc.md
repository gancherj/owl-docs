# Authenticated Encryption

In Owl, symmetric encryption is performed via _authenticated encryption_. We assume IND-CPA, INT-CTXT, and Key Privacy, which together state that encryptions under a correctly sampled secret key leak nothing about the message or the key other than the message's length. (See [The Owl paper](https://eprint.iacr.org/2023/473.pdf) for more details.) These are reasonable assumptions for modern ciphers, such as [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) or [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305). 

There are _two_ closely associated cryptographic abstractions Owl uses for symmetric encryption. The first, simply given by the name type `enckey T` (where `T` is a [type](./syntax.md#types)), is ["textbook" encryption](#textbook-encryption), where encryption takes two arguments --- the key and the message --- and decryption similarly takes two arguments --- the key and the ciphertext. In this "textbook" version, the nonce used by the symmetric cipher is randomly generated as part of compilation (and canonically appended to the ciphertext). 

> [!NOTE]
> Owl proves _asymptotic security_, which means that security issues arising from sampling the same nonce twice are out of scope. For this reason, the user should be aware of the concrete cipher implementation being used along with domain considerations when using textbook encryption.

In the [second version](#stateful-aead), we allow more precice control via a stateful AEAD primitive. In this version, the Owl program is able to use a monotonically increasing counter for encryption, and associate an AAD (additional authenticated data) to each ciphertext. This is the encryption scheme that is used for WireGuard. 

## Textbook Encryption

To obtain an encryption key, declare a name with `enckey T` as its name type, where `T` is a type. Note that since encryption does not hide message lengths, `T` cannot hold secret lengths. 

To encrypt, use `aenc(k, m)` where `k` is the key, and `m` is the message. This operation is well typed under the following two scenarios:

- If `k : Name(N)` where `N : enckey T`, `N` is a secret (i.e., `[N] !<= adv`), and `m : T`, then the result has type `c:Data<adv>{length(c) == cipherlen(m)}`; 
- If `k` and `m` are both public (i.e., subtype into `Data<adv>`), then the result is public and has no additional properties. Note that if `k : Name(N)` but `N` is corrupt (i.e., `[N] <= adv`), then `k : Data<adv>`. 

Above, `cipherlen(m)` is the function which statically computes the length of a symmetric ciphertext given the length of `m`. Owl does not assume any particular axioms about `cipherlen`. For example, `cipherlen(m)` could be `4 + length(m)` due to a four-byte tag for authentication.

On the other side, to decrypt, use `adec(k, c)` where `k` is the key, and `c` is the ciphertext. This operation is well typed under the following two scenarios:

- If `k : Name(N)` where `N : enckey T`, `N` is a secret, and `c : Data<adv>`, we return `Option T`; 
- If `k : Name(N)` where `N : enckey T`, and `N` is corrupt, and `c` is public, we return `Option Data<adv>`; and
- If `k` and `c` are both public (but `k` is not necessarily a key), we return `Data<adv>`. 

A complete example is given in `tests/success/encrypted_key.owl`.

## Stateful AEAD

An AEAD scheme, such as [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305), has the following interface: in addition to the key and message, the encryptor also provides a _nonce_ `N` and _associated data_ (AAD). (Note that this notion of a nonce is _different_ than Owl's use of the term "nonce" for opaque, random data.) For security, the nonce must not be reused for different encryptions. 

In return, encryption provides a ciphertext and and authentication tag, which Owl packages together. 
On the other side, the decryptor must provide not only the key and ciphertext/tag pair, but _also_ the nonce `N` and AAD being used. 

Since the nonce cannot be reused, modern protocols, such as [WireGuard](https://www.wireguard.com) and [HPKE](https://datatracker.ietf.org/doc/rfc9180/), typically implement the nonce using a monotonically increasing counter which the two parties maintain separately. Some protocols (such as HPKE) additionally _hide_ the nonce by XORing it with unique randomness each encryption, providing an anonymity guarantee. 

Owl can handle both of these scenarios. 

### Simple Monotonic Counter for Nonce
We will begin by first describing how Stateful AEAD is used with a simple increasing counter. First, let's look at the name declarations:

```owl
locality alice
locality bob

counter N @ alice
counter N_recv @ bob

name m : nonce @ alice // Just for defining the type of message to encrypt.

name k : st_aead Name(m)
            aad x. (x == 0x1234)
            nonce N 
          @ alice, bob
```

Before defining the encryption key, we need to define a _counter_. The important one here is `N`, which is the counter used for encryption. (The counter `N_recv` will be used for decryption; we will return to this later.) We can see this in the name type for the encryption key `k`; in addition to the type being encrypted (here, `Name(m)`) we also see two additional pieces of metadata.  The _aad field_ `aad x. (x == 0x1234)` states that we are only allowing encryptions where the AAD is exactly `0x1234`; and the _nonce field_ `N` states that we are using `N` for encryption. 

Now, let's look at the way we encrypt:
```owl
def client() @ alice : Unit = 
    let c =  st_aead_enc<N>(get(k), get(m), 0x1234) in 
    output c;
    ()
```

To encrypt, we use the cryptographic operation `st_aead_enc`, which takes one argument in angle brackets --- the name of the counter used for encryption --- and three ordinary arguments, for the key, message, and AAD. 
Whenever we call `st_aead_enc`, the extracted protocol will read the current value of `N`, use that for the encryption nonce, and increment `N` as part of encryption; in this way, we guarantee by construction that all nonces used are unique. 

Just as in [textbook encryption](#textbook-encryption), the typing rules are split according to whether the key `k` is secret. We additionally require that if `k` is secret, the AAD must be correct. Additionally, since the counter `N` is compiled to local state, we require that `st_aead_enc<N>(...)` is only called at locality `alice`.

Now, looking at decryption:

```owl
def server(my_aad : Data<adv>) @ bob : Unit = 
    input c in
    let ctr = get_counter N_recv in 
    inc_counter N_recv;
    corr_case k in
    case st_aead_dec(get(k), c, my_aad, ctr) {
        | Some x => assert(sec(k) ==> (x == get(m) /\ my_aad == 0x1234))
        | None => ()
    }
```

For the purpose of demonstration, we have the server take the AAD `my_aad` as input. (In reality, the AAD would either be computed before decryption, or perhaps packaged in a struct alongside the ciphertext.) We see that `st_aead_dec` takes four arguments, instead of two: the key, ciphertext, AAD, and counter. To retrive the counter, we call `get_counter N_recv`. We then increment the counter using `inc_counter N_recv`. (Since we only require the counter is unique _per encryption_, it is always sound to read and increment the counter.) If decryption succeeds and the key is secret, the server learns that the message is authentic and the AAD predicate is true. 

### Using a Pattern for Fine-Grained Nonce Control

In certain protocols (such as HPKE) we don't want to have the nonce be _verbatim_ the counter, but instead a _function of_ the counter. This allows, for example, the counter's value to be randomly offset by a _base_ (via an XOR). 

We support this style of nonce in the following way:

```owl
locality alice
locality bob

counter N @ alice
counter N_recv @ bob

name m : nonce @ alice // just for defining the type of message

name base : nonce |counter| @ alice, bob 

corr adv ==> [base]

name k : st_aead Name(m)
            aad x. (x == 0x1234)
            nonce N
            // optionally: a pattern for the counter
            pattern i. xor(i, get(base)) 
        @ alice, bob
```

The difference is we now have a name `base`, with type `nonce |counter|`. This name type is similar to the regular `nonce` type, but is required to have length of counters (written `|counter|`), rather than the default length of nonces, `|nonce|`. Via a `corr` declaration, we require that the `base` is public. 
We then declare `st_aead` with a _pattern_, which states how the counter should be transformed before encrypting. Here, we transform the nonce by XORing it with the base. For the pattern to be accepted by Owl, Owl must verify that it is injective.  

Now, for encryption and decryption:

```owl
def client() @ alice : Unit = 
    let my_base = get(base) in 
    let c =  st_aead_enc<N, pattern i. xor(i, my_base)>(get(k), get(m), 0x1234) in 
    output c;
    ()

def server() @ bob : Unit = 
    input c in 
    let base = get(base) in 
    let ctr = get_counter N_recv in 
    corr_case k in 
    case st_aead_dec(get(k), c, 0x1234, xor(ctr, base)) {
        | Some x => assert(sec(k) ==> (x == get(m) ))
        | None => ()
    }
```

For encryption, we must add the pattern to the call to `enc_st_aead`. Note here that the pattern may involve local computations (such as `my_base`); Owl verifies that the pattern given is equivalent to the pattern attached to the key. For decryption, we simply pass the derived nonce directly to `st_aead_dec`. 

> [!NOTE]
> The purpose of XORing the counter with a base is to provide anonymity; as such, HPKE asserts that the `base` should be secret.  However, for Owl, the counter must be public, since the ordinary security model of AEAD assumes public counters. 



