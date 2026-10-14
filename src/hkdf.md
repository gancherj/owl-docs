# HKDF and KDF Scopes

Most protocols performing key exchange include _key derivation_, where secret keys are created out of (a combination of) prior protocol secrets. Owl supports reasoning about key derivation via a type-based model of [HKDF](https://en.wikipedia.org/wiki/HKDF), the dominant key derivation algorithm used in modern protocols.  

## Background on HKDF, and Assumptions

The HKDF algorithm (combining the `extract` and `expand` phases) takes four arguments:

1. A `salt`;
2. An `IKM` (Input Keying Material);
3. An `info`, for contextual information; and 
4. A desired length, `N`.

Given these arguments, `HKDF` deterministically outputs `N` bytes. The security guarantees assumed of HKDF [are](https://eprint.iacr.org/2023/861.pdf) [complex](https://eprint.iacr.org/2017/517), but we outline them here. 
Technically, Owl assumes that `HKDF` is a Dual-PRF (i.e., is a PRF when keyed either in `salt` or `IKM` position); and that the [PRF-ODH assumption](https://eprint.iacr.org/2017/517) holds for HKDF.
Intuitively, given an HKDF call `res = HKDF(salt, ikm, info, N)`, we assume that the output `res` is computationally indistinguishable from uniform to an attacker:

- When the `salt` is uniformly random, and secret; OR 
- The `IKM` contains secret uniform randomness; OR
- The `IKM` contains a Diffie-Hellman shared secret, where both Diffie-Hellman keys are secret.

We assume that the `info` may be public and adversarially-controlled. 


Additionally, in certain instances, the HKDF algorithm is allowed to leak values of the form `HKDF(salt, h^x, info, N)` to the adversary, even when `x` is a secret and `h` is adversarially-chosen. (This is the PRF-ODH assumption).

## KDF Scopes

Many protocols use HKDF multiple times in a _chain_ or _key schedule_, where the output of one KDF call is used as the salt or IKM for the next.
To model such a protocol in Owl, we need to give name types to every KDF output that is used as a key in the protocol.
For soundness, we also need to make sure that two different uses of KDF in the protocol can't produce the same value: if this were possible, we might give the same value two different names, which could lead to a secret leaking to the adversary.

To specify this information in Owl, we use a _KDF scope_, which collects together:
- all the base names (plain random KDF keys and Diffie-Hellman shared secrets) used as inputs to KDF calls, and
- a list of _rules_, each of which specifies one way that the keys can be used with HKDF.

For example:
```owl
locality alice
locality bob

name m1 : nonce @ alice
name m2 : nonce @ alice

kdf_scope Handshake {
    name psk : kdfkey @ alice, bob
    name a : DH @ alice
    name b : DH @ bob

    odh L_hs   : psk, dh_ss(a, b), 0x01 -> strict kdfkey || strict enckey Name(m1)
    kdf L_data : KDF<L_hs; kdfkey || enckey; 0>, 0x, 0x02 -> strict enckey Name(m2)
}
```

The scope declares a pre-shared key `psk` (of name type `kdfkey`) and two Diffie-Hellman keys, `a` and `b`.
Each rule is written as `salt, ikm, info -> outputs`:

- `L_hs` says that HKDF with `psk` as the salt, the Diffie-Hellman shared secret of `a` and `b` as the IKM, and `0x01` as the info gives two outputs: a new KDF key (call it a "chaining key") and an encryption key for `m1`.
- `L_data` says that HKDF with the chaining key from `L_hs` as the salt, an empty IKM, and `0x02` as the info gives an encryption key for `m2`.

Scopes are not treated as namespaces. The names declared inside it are ordinary top-level names, so we don't need to mention the scope name in the rest of the protocol---we would just write `get(a)`, etc.

Besides names and rules, a scope may contain helper declarations such as `func`, `predicate`, and `corr`, which behave exactly the same as outside the scope.

A protocol can contain multiple scopes. Importantly, scopes are _disjoint_ from one another: Owl forbids using names from one KDF scope as inputs in another KDF scope's rules.
This is important for soundness, since it allows us to analyze each scope independently to make sure the rules are disjoint.

### Rules

A rule has the form

```owl
kdf L : salt, ikm, info -> out_1 || ... || out_m
```

where:

- The **salt** is either a key from the scope (a `kdfkey` declared in it, or a `kdfkey` output of one of its rules) or a public value, such as a hex constant.
- The **IKM** is one or more element concatenated with `++`. Each element is a key from the scope, a Diffie-Hellman shared secret from two DH keys in the scope, or a public value. We write the shared secret of two `DH` names `X` and `Y` as `dh_ss(X, Y)`, which is shorthand for `dh_combine(dhpk(get(X)), get(Y))`. A rule whose IKM contains a `dh_ss` must be declared with `odh` instead of `kdf`, signifying that its security relies on the PRF-ODH crypto assumption.
- The **info** is a public value.

When defining a rule, we can write a bare name `psk` instead of `get(psk)`. Importantly, each rule must use at least one key of its own scope in its salt or IKM; otherwise, the rule is not "bound" to the scope and so it might collide with KDF rules from other scopes.

Each output `out_j` is a name type, optionally annotated with `strict` or `public` (see [below](#strict-and-public-outputs)). The output names must be uniformly random, since HKDF produces uniformly random output. So the allowed name types are `nonce`, `enckey`, `st_aead`, `mackey`, and `kdfkey`, but not `DH` or `sigkey`.

### Derived Names

Derived names are the names generated as outputs from KDF rules. The syntax for a derived name is `KDF<L; kinds; j>` for output number `j` (counting from zero) of rule `L`, where `kinds` lists the name kinds (`enckey`, `nonce`, etc) of all of `L`'s outputs. For example, the chaining key in our example is `KDF<L_hs; kdfkey || enckey; 0>`, and the encryption key for `m1` is `KDF<L_hs; kdfkey || enckey; 1>`. Derived names behave just like base names declared with `name _`, so they can appear in types like `Name(...)`, in `corr` declarations, and as an input to other rules in the same scope (as in `L_data` above).

### `strict` and `public` Outputs

By default, Owl does not assume that a derived name is secret, even if the inputs that it was generated from were secret.
In many protocols, such an assumption may be necessary or useful. So Owl provides the `strict` annotation on KDF rule outputs, which specifies that the rule output is secret whenever at least one of the rule's input keys is secret. The `public` annotation says the opposite, i.e., the rule output is always known to the adversary (similar to a [`corr` declaration](./syntax.md#corruption-declarations)).

Owl _does_ assume that if none of a rule's keys are secret, then all of its outputs are corrupt. This is because the adversary could just do the same KDF computation itself.

### Advanced features: Parameters, Indices, and `where` Clauses

Rules can take index parameters, like names, and bytestring parameters. Bytestring parameters are ghost values that stand for parts of the input that vary between calls. A rule can restrict these parameters with a `where` clause. For example:

```owl
kdf_scope S {
    name k : kdfkey @ alice

    kdf L_mac                        : k, 0x, 0x  -> strict mackey Data<adv>
    kdf L_ctx(ctx) where (ctx != 0x) : k, 0x, ctx -> strict enckey Name(m)
}
```

In this example, we want to generate a MAC key when the info argument is empty, but an encryption key for all other choices of the info argument. Here `L_ctx(0x01)` refers to the instance of rule `L_ctx` with `ctx = 0x01`, and its output is `KDF<L_ctx(0x01); enckey; 0>`. The `where` clause keeps `L_ctx` disjoint from `L_mac`: without it, `L_ctx(0x)` would have exactly the same inputs as `L_mac`, so `KDF<L_ctx(0x); mackey; 0>` and `KDF<L_mac; mackey; 0>` would both be names the same value.

Each index and bytestring parameter must appear somewhere in the rule's salt, IKM, or info, since otherwise two choices of a "free" parameter could again give two names for the same value.

## Calling KDF

To call HKDF, use the following syntax:

```owl
let derived_key = kdf<HINTS; KINDS; j>(salt, ikm, info) in ...
```

`KINDS` lists the name kinds of the outputs, separated by `||` (as in derived names), and `j` picks which output from `KINDS` should be returned. `HINTS` names the rule instances (e.g., `L_hs`, `L<i>`, or `L_ctx(0x01)`) that we expect the call to match. If the call can match one rule in one branch of the typechecker and another rule in another branch, we list both separated by commas; if all inputs are public, the list can be empty. All hints in a call must come from the same KDF scope.

In [the compiler](./compiler.md), a call `kdf<...; KINDS; j>(salt, ikm, info)` runs HKDF with the given salt, IKM, and info, asking for enough bytes for all of `KINDS`, and returns the slice that belongs to output `j`. Hints are ghost, since their role is to give an Owl name type for the KDF output, so the compiler erases them.

### Typing Rule for KDF

Like other cryptographic operations in Owl, a `kdf` call can have multiple valid outcomes:

- **All inputs are public.** Then the adversary can compute the output too, so it is given type `Data<adv>`.
- **Exactly one hint matches.** The typechecker proves that the call's arguments are exactly the inputs of the matching rule `L`, and that one of that rule's inputs is secret. Then the output is given the derived name type `Name(KDF<L; KINDS; j>)`. For a `strict` output, Owl also adds the fact that the name is secret.
- **No rule matches.** Otherwise, the typechecker tries to prove that the call doesn't match _any_ rule of the scope with a secret key input. For example, this could happen if a party hashes its secret DH key with a public key from the attacker. By the assumptions [above](#background-on-hkdf-and-assumptions), an output from such a call tells the attacker nothing about the scope's keys or its other outputs, so it is given type `Data<adv>`.

When Owl can't establish any of these cases, it reports an error. Usually, this indicates that the typechecker doesn't know whether some rule applies; adding `corr_case` on the secrecy of input keys or `pcase` on whether inputs match their intended values typically helps.

For example, here's how Alice might use the `Handshake` scope from [above](#kdf-scopes). For simplicity, suppose she gets Bob's public key as an argument:

```owl
corr [KDF<L_hs; kdfkey || enckey; 1>] ==> [m1]
corr [KDF<L_data; enckey; 0>] ==> [m2]

def alice_main(pk_b : dhpk(b)) @ alice : Unit =
    corr_case psk in
    corr_case a in
    corr_case b in
    let ss = dh_combine(pk_b, get(a)) in
    let ck = kdf<L_hs; kdfkey || enckey; 0>(get(psk), ss, 0x01) in
    let k1 = kdf<L_hs; kdfkey || enckey; 1>(get(psk), ss, 0x01) in
    let c1 = aenc(k1, get(m1)) in
    output c1;
    let k2 = kdf<L_data; enckey; 0>(ck, 0x, 0x02) in
    let c2 = aenc(k2, get(m2)) in
    output c2
```

The three `corr_case`s split the typechecker into branches according to which of `psk`, `a`, and `b` are secret. In each branch where `psk` is secret, or both `a` and `b` are, the two `L_hs` calls match their hint, so `ck` and `k1` get the types of the derived names (and are secret, since the outputs are `strict`). The `L_data` call then matches as well, since `ck` is a secret key from the scope. In the remaining branches, all the calls return `Data<adv>`. We have the two `corr` axioms at the top stating that `m1` and `m2` are assumed to be public in these cases, so it is safe to encrypt them.

**Reflecting KDF in Ghost.** In all cases, the result of `kdf<HINTS; KINDS; j>(salt, ikm, info)` is refined to be equal to `gkdf<KINDS; j>(salt, ikm, info)`, which is a ghost-level [atomic expression](./syntax.md) for the result of the call. This is handy for stating facts about derived keys in refinements and assertions.

## KDF Scope Well-formedness

Owl requires all KDF scopes to mantain some well-formedness properties, so that it is sound for us to typecheck KDF calls against only their own scopes. At a high level:

- **Every rule must be bound to its scope.** Every rule must use a name from its own scope as its salt or in its IKM, and no secret names from anywhere else.
- **Rules don't overlap.** No two rules, and no two instances of one rule with different index or bytestring parameters, can ever have the same salt, IKM, and info. For example, `kdf L(x, y) : k, x ++ y, 0x -> ...` overlaps with itself, since `L(0x12, 0x34)` and `L(0x1234, 0x)` have the same IKM. Typically, we provide domain separation with different info constants or different salts, or with a `where` clause, as in `L_ctx` above.
- **No key cycles.** An output can't encrypt (or MAC) a key that it was derived from, since our crypto assumptions break if a key can encrypt itself.

