# Authenticated Encryption

In Owl, symmetric encryption is performed via _authenticated encryption_. We assume IND-CPA, INT-CTXT, and Key Privacy (TODO), which are reasonable assumptions for modern ciphers (e.g., AES-GCM or ChaCha TODO). These cryptographic assumptions are borne out of the typing rules associated to encryption and decryption.

There are _two_ closely associated cryptographic abstractions Owl uses for symmetric encryption. The first, simply given by the name type `enckey T` (where `T` is a [type](./syntax.md#types)), is ["textbook" encryption](#textbook-encryption), where encryption takes two arguments --- the key and the message --- and decryption similarly takes two arguments --- the key and the ciphertext. In this "textbook" version, the nonce used by the symmetric cipher is randomly generated as part of compilation. 

In the [second version](#stateful-aead), we allow more precice control via a stateful AEAD primitive. In this version, the Owl program is able to control the nonce used for encryption, and associate an AAD (additional authenticated data) to each ciphertext. 

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

## Stateful AEAD



