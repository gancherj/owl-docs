# Diffie-Hellman and HKDF

Most protocols performing key exchange include _key derivation_, where secret keys are created out of (a combination of) prior protocol secrets. Owl supports reasoning about key derivation via a type-based model of [HKDF](https://en.wikipedia.org/wiki/HKDF), the dominant key derivation algorithm used in modern protocols.  

## Background on HKDF, and Assumptions

The HKDF algorithm (combining the `extract` and `expand` phases) takes four arguments:

1. A `salt`;
2. An `IKM` (Input Keying Material);
3. An `info`, for contextual information; and 
4. A desired length, `N`.

Given these arguments, `HKDF` deterministically outputs `N` bytes. The security guarantees assumed of HKDF [are](https://eprint.iacr.org/2023/861.pdf) [complex](https://eprint.iacr.org/2017/517), but we outline them here. 
Technically, Owl assumes that `HKDF` is a Dual-PRF (is a PRF when keyed either in `salt` or `IKM` position); and that the [PRF-ODH assumption](https://eprint.iacr.org/2017/517) holds for HKDF. 
Intuitively, given an HKDF call `res = HKDF(salt, info, ikm, N)`, we assume that the output `res` is computationally indistinguishable from uniform to an attacker:

- When the `salt` is uniformly random, and secret; OR 
- The `IKM` contains secret uniform randomness; OR
- The `IKM` contains a Diffie-Hellman shared secret, where both Diffie-Hellman keys are secret.

We assume that the `info` may be public and adversarially-controlled. 


Additionally, in certain instances, the HKDF algorithm is allowed to leak values of the form `HKDF(salt, h^x, ikm, N)` to the adversary, even when `x` is a secret and `h` is adversarially-chosen. (This is the PRF-ODH assumption).

## Name Types for HKDF

Intuitively, there are three different ways of using HKDF (often which are used simultaneously): with a uniform secret in salt position; with a uniform secret in IKM position; and with a Diffie-Hellman secret in IKM position.
The first two cases are handled by a special name type, while the latter is handled by a [special declaration](#odh-declarations).

### Uniform Secrets in Salt Position: `kdf` type 

To specify an HKDF secret in salt position, one uses the following name type:

```owl
name k : kdf {ikm info.
    PROPERTY_1 -> NAME ROW_1, 
    ...
    PROPERTY_k -> NAME ROW_k
} @ ...
```
where `PROPERTY_i` is a proposition that can make use of the variables `ikm` and `info` (referring to the other arguments to the current HKDF call); and each `NAME ROW` has the following syntax:

```
nt ::= .. // name type
<annotation> := public | strict
ELEM ::= nt | <annotation> nt
NAME ROW ::= ELEM || ... || ELEM
```

Thus each `NAME ROW` is a list of `ELEM`s, separated by `||`. Each `ELEM` is a name type, with an optional [annotation](#name-annotations-for-hkdf). 
As is hinted here, and [outlined below](#calling-kdf), KDF calls result in fresh Owl names for each (secret) input given. Each name type appearing in a KDF name type must be a _uniform one_ (e.g., `nonce` or `enckey`, and not, for example a signing key); this corresponds to the assumption that HKDF outputs uniform randomness.

An example name declaration KDF type is below:
```owl
name k : kdf {ikm info.
    (info == 0x01) -> enckey Name(alice1),
    (info == 0x02) -> strict kdf {ikm info.
        (info == 0x01) -> enckey Name(alice2),
        (info == 0x02) -> kdf {ikm info.
            (info == 0x01) -> enckey Name(alice3)
        }
    }
} @ alice, bob
```

This declares a shared key `k` such that:

- If it is hashed with an `info = 0x01`, it produces an encryption key for `Name(alice1)`;
- If it is hashed with an `info = 0x02`, it produces a [strict](#name-annotations-for-hkdf) KDF key such that: 
    - If hashed with `info = 0x01`, it produces an encryption key for `Name(alice2)`; and 
    - If hashes with `info = 0x02`, produces a KDF key such that: 
        - If hashed with `info = 0x01`, produces an encryption key for `Name(alice3)`.

The complete example can be found [here](https://github.com/secure-foundations/owl/blob/main/tests/success/kdf-enc.owl). 


### Uniform Secrets in IKM Position: `dualkdf` type 

To specify a uniform secret in IKM position, one uses the `dualkdf` nametype:

```owl
name k2 : dualkdf {salt info.
    PROPERTY_1 -> NAME ROW_1, 
    ...
    PROPERTY_k -> NAME ROW_k
} @ ...
```

It is exactly the same as the `kdf` type above, except binds the value of `salt` and `info` instead of `ikm` and `info`.





### Name Annotations for HKDF

There are two annotations that one can place on each name type inside of a KDF: `public`, and `strict`. 
The `public` annotation simply says that the result of the hash should be considered a public piece of randomness (similarly to how we can use [`corr` declarations](./syntax.md#corruption-declarations) to assume a given name is public). 

The `strict` annotation has to do with Owl's information flow assumptions about the output name from the HKDF call. If the name `n` is returned by the KDF call `kdf<...>(x, y, z)` (and hence there is a genuine secret in `x` or `y`, as [described below](#calling-kdf)), by default, Owl does not assume that `n` is a secret. 
This behavior may be desired if one is modeling a corruption scenario where one hashes a secret using ephemeral information, stores the resulting key on disk, and then the attacker gains access to the disk. 

However, in certain secruity analyses, it may be desirable to assume that if we hash secrets, then the result is automatically a secret. This can be achieved by annotating the name type with `strict`.  


### `self` parameter for `kdf`/`dualkdf`

In addition to the arguments `ikm/info` and `salt/info` for `kdf` and `dualkdf` respectively, one can also optionally make reference to the key being defined using `self`:

```owl
nametype shared_secret_t = 
    kdf {ikm info self. 
        ... // Here, self is equal to the key being defined
    
    }
```

This is useful, for example, to make reference to a "sibling" hash in a hash chain.
However, such a `self` parameter should be used with caution, as it is still **experimental**.


## ODH Declarations

The third way to declare that a secret is suitable for calling HKDF is an _ODH declaration_, standing for Oracle Diffie-Hellman. An example ODH declaration is given below:

```owl
locality alice

name X : DH @ alice
name Y : DH @ alice

name n : nonce @ alice

odh L : 
    X, Y -> {salt info.
        salt == 0x -> strict enckey Name(n)
    }
```

To use `odh`, one first needs two names of name type `DH`. Then, we give an identifier for the ODH declaration (here, `L`). Then, after specifying the two names `X` and `Y`, and after the `->`, we have the same syntax as a [`dualkdf` name](#uniform-secrets-in-ikm-position-dualkdf-type).

ODH declarations can be indexed, if one of the DH names have an index:
```owl
...

name X<i> : DH @ alice
name Y : DH @ alice

odh L<i> : 
    X<i>, Y -> { ... }
```



## Calling KDF

To call HKDF, we use the following syntax:

```owl
let derived_key = kdf<SALT_HINTS; IKM_HINTS; NAME_ROW; INDEX>(salt, ikm, info) in 
...
```

The first two parameteters to `kdf`, `SALT_HINTS` and `IKM_HINTS`, are hints to the type checker to prove that the given KDF call is a secure one, as will be defined below. These parameters have the following syntax:

```
HINT ::= PositiveInt // Used for indexing into the desired row for a kdf / dualkdf key

// We may have multiple hints, if there are multiple possible values for the salt key. Typically, there is only one. 
// It may be empty, if no salt key is used.
SALT_HINTS ::= comma_separated_list_of(HINT) 

IKM_HINT ::= HINT // Similar to the hint for a salt key. Used for a dualkdf key.
            // Used for an ODH call.
            | odh ODH_DECL [ HINT ]

// Also may be nonempty if no key / shared secre in IKM position is to be used. 
IKM_HINTS ::= comma_separated_list_of(IKM_HINT)


NAME_KIND ::= kdfkey | enckey | mackey | nonce | "nonce" "|" SYM_LEN "|" // Essentially a name type, but without the corresponding type annotation. 
NAME_ROW ::= <empty> | NAME_KIND "||" NAME_ROW // A list of name kinds separated by ||

INDEX ::= PositiveInt // Used for indexing into the name row
```

In [the compiler](./compiler.md), a call to `kdf<..; ...; NAME_ROW; idx>(x, y, z)`  is interpreted as `HKDF.Expand(HKDF.Extract(x, y,z ), N)`, where `N` is defined by the length of `NAME_ROW[i]`.

### Typing Rule for KDF

We first give an overview of how KDF operates before going into detail.

### Overview of using KDF in Owl

The role of `kdf` is to return a fresh, random secret. We encode this in Owl by introducing a new expression form for names: `KDF<NAME_ROW; idx; nt>(x, y, z)`, which corresponds to the result of calling `kdf` with the given `NAME_ROW`, index `idx`, and inputs `x, y, z`. Here, `nt` is the name type that is assigned to the result of the KDF. 

Similar to other cryptographic operations, a call to `kdf<..;..;NAME_ROW:idx>(x, y, z)` has three possible valid outcomes: either:

- All inputs are public, in which case the output will be public; or 
- The type checker can prove that the inputs are suitably secret and well-typed, in which case the output will have type `Name(KDF<NAME_ROW; idx; nt>(x, y, z))`, where `nt` is the name type uniquely determined by the inputs to the KDF; or 
- A certain condition related to the [PRF-ODH](#background-on-hkdf-and-assumptions) holds, wheree we are hashing a value of the form `h^x`, where `x` is secret, but `h` is "out of bounds" for the protocol (detailed below). In this case, the output will also be public.

**Reflecting KDF in Ghost.** In all cases, the output of KDF is refined to be equal to `gkdf<NAME_ROW; idx>(x, y, z)`, which is a ghost-level [atomic expression](./syntax.md) for the result of the KDF call. 

### Details of Typing Rule

TODO

