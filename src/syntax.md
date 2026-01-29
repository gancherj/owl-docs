# Syntax

Below serves as a reference to the syntax of Owl.

## Overview

Owl is composed of _specification-level_ objects, such as [names](#names) and [(data) types](#types), and executable [expressions](#expressions), which are meant to be run. 

The specification-specific syntax of Owl is stratified in a number of layers: 
- [names](#names), which are type-level cryptographic keys;
- [labels](#labels), which drive Owl's information-flow typing rules;
- [types](#types), which specify the types of data; and
- [name types](#name-types), which can be thought of as specifications for names (as types are specifications for data). 


## Names

Names in Owl are cryptographic keys which are reflected to the type level. Names can either be _base names_, given by an identifier (e.g., `n`), or _derived_ names of the form `KDF<...>(...)` (explained below).


Base names are created by a _name declaration_:

```owl
name k : nt @ loc
```

where `nt` is a [name type](#name-types) and `loc` is a [locality](#localities). 
In an expression, you can obtain the value of `k` by calling `get(k)` (this will not work if the code is running at a different locality than the name, however).
The type of `get(k)` is `Name(k)` (explained [below](#types)). 

Name declarations (among other things) can be _indexed_, as so:

```owl
name k<i, j @ k> : enckey t @ loc<k>
```

<!-- Is the dual use of `k` intended here? -->
This creates a name `k` indexed by two _session IDs_, `i` and `j`, and a _party ID_ `k`. All indices may be used in the type `t`, but only party IDs may be used in the associated locality. 

### KDF Names

Aside from assuming names as input to the protocol, names can also be _derived_ via a call to a key derivation function. Owl currently supports HKDF. 
A secure output of HKDF results in value of type `Name(KDF<nk_1 || ... || nk_n; i; nt>(a, b, c))`.
Details about the KDF operation and `KDF` name are specified [here](./hkdf.md).

### Name Types

Each name in Owl has a _name type_, which is intuitively the cryptographic permissions that the corresponding key is allowed to be used for. 
Each [cryptographic operation](./crypto.md) has a corresponding name type.



### Grammar 

Names:

```
N ::= n // Base name
   |  n<i@j> // Indexed name
   |  KDF<nk_1 || ... || nk_n; i; nt>(a, b, c) // KDF Name
```

Name Types:

Below is an (incomplete) list of some name types supported by Owl:

- `DH`, for [Diffie-Hellman](./hkdf.md);
- `nonce`, for [random, unstructured secrets](./nonce.md)
- `nonce |LC|`, for [random, unstructured secrets](./nonce.md) where `|LC|` is a [length constant](#length-constants);
- `sigkey T`, for [signing keys](./signatures.md);
- `enckey T`, for [encryption keys](./aenc.md);
- `pkekey T`, for [public encryption keys](./pke.md);
- `mackey T`, for [MAC keys](./mac.md);
- `NT<..>(x, y, .., z)` for name type abbreviations. Here, `<..>` contains (optional) [index](#indices) parameters; while `x, y, ..., z` are arguments given as [atomic expressions](#atomic-expressions);
- `st_aead ...`, for stateful AEAD [details here](./aenc.md);
- `kdf ...` and `dualkdf ...` for KDF keys [details here](./hkdf.md).


## Labels

Labels form the basis of Owl's information flow analysis. 
The two most important labels are _name labels_ and the _adversary labels_.
If `N` is a [name](#names), then `[N]` is the label associated to `N`. (For example, `get(N)` has label `[N]`). The adversary label, `adv`, is the label for public data. 
Owl labels form a _semilattice_, meaning that there is a binary operation `/\` between labels that constructs the least upper bound of the two labels. 

Here is an example piece of code that exercises labels:
```owl
locality alice
name n : nonce @ alice
name m : nonce @ alice

def foo() @ alice : Unit = 
    input i in 
    let j : Data<adv> = i in 
    let x : Data<[n]> = get(n) in 
    let y : Data<[m]> = get(m) in 
    let z : Data<[n] /\ [m]> = x ++ y in 
    ()
```
After defining two names `n` and `m`, we take an input `i` from the network inside of `foo`. 
We then assign `i` to `j`, and give it the type `Data<adv>`; this type represents "data labelled at `adv`". Hence, `x` has type `Data<[n]>`, `y` has type `Data<[m]>`, and `x ++ y` has type `Data<[n] /\ [m]>` (since we are combining `x` and `y` through concatenation).

### Indexed joins of labels

In more complicated code, one might have an indexed name `n<i>` and need to represent the label for data that depends on _some_ `n<i>`, but we don't know which one. In this case, one can use an _indexed join_:

```owl
locality alice
name n<i> : nonce @ alice

def foo<i>() @ alice : Unit = 
    input i in 

    let x : Data<[n<i>]> = get(n<i>) in 
    let y : Data</\_k [n<k>]> = x in 
    ()
```

Here, the label `/\_k [n<k>]` is the join over all labels of the form `[n<k>]`, for all `k`. 

### Information Flow Ordering

Given two labels `L1` and `L2`, the [proposition](#propositions) `L1 <= L2` states that label `L1` flows to `L2`. The bottom of the information flow lattice is `static` (so `static` flows to everything). 

We use the information flow order to define corruption. We say that the name `n` is _corrupt_ if `[n] <= adv`, and is _secret_ otherwise (which we write as `[n] !<= adv`).

A central part of Owl is that the information flow ordering is influenced by crytographic primitives. If `n` is an encryption key for data labeled at `L`, then we get that `L <= [n]`. More details are given when discussing [cryptographic operations](./crypto.md).

### Grammar

```
L ::= [N]
    | static
    | adv
    | L /\ L
    | /\_i L   // Join over index
```

In addition to the above, there are a few labels internal to the implementation of Owl --- `top` and `ghost` --- but these can be safely ignored in user code.

## Types

Cryptographic security in Owl is expressed via types. Owl types can be thought of as having two components: a _secrecy_ component, expressed using information-flow labels; and an _integrity_ component, expressed using refinement and singleton types. As is common in information-flow type systems, Owl types support _subtyping_, which states when data in one type can be considered to have another type. 

### Basic Types

Logically, _all_ data in Owl are bytestrings --- even structs and enums, which should be thought of as holding their parsed representations (where structs have their field concatenated, and enums are implicitly tagged unions). 

#### Data Types

Suppose `L` and `L'` are [labels](#labels), and `a` is an [atomic expression](#atomic-expressions). Then, the types `Data<L>`, `Data<L, |L|>` and `Data<L> |a|` all represent arbitrary data (i.e., bytestrings) with various secrecy and integrity information.

- The type `Data<L>` represents arbitrary data with secrecy `L`.
- The type `Data<L, |L'|>` represents arbitrary data with secrecy `L`, where the _length_ of that data has label `L'`. This is mostly used in the form `Data<L, |adv|>`, which represents public-length data. 
- The type `Data<L> |a|` represents data with secrecy `L`, where the length of that data is statically known to have length equal to the value of `a`. The most common use case here is where `a` is a constant: e.g., `Data<adv> |32|`, for 32-byte length data, or `Data<adv> | |nonce| |`, where `|nonce|` is the constant for the length of a `nonce` name. 

The above types use the information-flow lattice to define the subtyping order. For example, `Data<L>` is a subtype of `Data<L'>` whenever `L <= L'. 

A unifying principle of Owl is that _all data are bytestrings_. Thus, the (non-ghost component 

#### Unit and Lemma

The type `Unit` (with distinguished element `()`) behaves as it does in other languages. Importantly, however, the `Unit` type can be [_refined_](#refinement-types), just as any other type can be. Thus, we can say things like:

```owl
locality alice

def foo(x : Data<adv>, pf : (_:Unit{x != 0x1234})) @ alice : Unit = 
    ()

```

Here, we refine the `Unit` type with a proof that `x` is not equal to `0x1234`. (We could have refined `x` as well, but it is often convenient to detatch the proof from the data). In this special case, we can also type:

```owl
def foo(x : Data<adv>, pf : Lemma{x != 0x1234}) @ alice : Unit = 
    ()
```

Here, `Lemma{P}` is sugar for `_:Unit{P}`.

#### Bool

If `L` is an information flow label, then `Bool<L>` is the type of booleans with secrecy level `L`. Just like with `Data`, `Bool` respects subtyping with respect to the level `L`.


### Refinement Types

To express arbitrary integrity properties, Owl supports _refinement types_. If `T` is a type, and `P` is a [proposition](#propositions) that mentions `x : T`, then `x:T{P}` is a type. Refinement types in Owl behave similarly to [F*](https://fstar-lang.org/tutorial/), and are checked using an SMT solver. 

### Structs, Enums, and Option Types

Owl supports byte-precise data types via structs and enums. 

#### Structs

Below is a simple struct, used in our formalization of WireGuard:

```owl
// And the transport layer message
struct transp {
      _transp_tag : Const(0x04000000)
    , _transp_receiver : Data<adv> |4|
    , _transp_counter  : Data<adv> | |counter| | 
    , _transp_packet   : Data<adv> 
}
```

A struct is defined by a number of fields, specified by an identifier and a type. 
The naming scheme we use here for each field (`_struct_field`) is not necessary, but useful for namespacing. 
The first field here has a [const](#const) type, while the next two are [data types refined with a length](#data-types), and the last is simply public data. While the above struct is used for a network format, Owl structs can also be used for internal data structures for protocols, such as a record of the most recently derived secret keys. 

##### Dependent Structs 

The types in structs can depend on previous values:
```owl
locality alice

struct ne_pair {
    x : Data<adv> | 2 |, 
    y : (z:Data<adv> | 2 | {z != x}) 
}

def foo() @ alice : Unit = 
    let v : ne_pair = ne_pair(0x1234, 0x5678) in  // OK 
    let v2 : ne_pair = ne_pair(0x1234, 0x1234) in  // Fails to type check
    ()
```

##### Invalid Structs (and other data)

Since [all data in Owl are byte strings](#basic-types), building a struct may have meaning even if the corresponding type refinements in the struct do not hold. We model this through the following strategy: _applying invalid arguments to a function results in the information-flow approximation to their type_. In the case of structs, this is justified since a constructor for a struct in Owl's semantics is simply a function which concatenates its arguments together. 

We can see this here:
```owl

// tst.owl

locality alice

name n : nonce @ alice

struct ne_pair {
    x : Data<adv> | 2 |, 
    y : (z:Data<adv> | 2 | {z != x}) 
}

def foo() @ alice : Unit = 
    let v : ne_pair = ne_pair(0x1234, 0x5678) in 
    let v2 = ne_pair(get(n), 0x) in  // 0x = empty byte string
    debug printTyOf(v); 
    debug printTyOf(v2); 
    ()
```

When we run the above code with `cabal run owl -- tst.owl --log-typecheck`, we get the following output:

```
  Type for v: ne_pair
  Type for v2: .res:(Data<[n]>){.res == ne_pair(get(n), 0x)}
```

Here, `v` is a valid `ne_pair` (because all relevant subtyping queries succeeded), while `v2` is not. In this case, Owl simply re-interprets `ne_pair` as the concatenation function. 

In the type refinement for `v2`, we see that Owl remembers that the value of `v2` is equal to `ne_pair(get(n), 0x)`. (In type refinements, `ne_pair` is interpreted as a pure function on byte strings.)

(Details for the `debug` expression are given [here](#debug-expressions).)

##### Parsing

Since a value of type `ne_pair` is regarded as a specially formatted byte string, we do not destruct it via `.` syntax, as one does in C. Instead, we have _parse_ statements:

```owl
locality alice

name n : nonce @ alice

struct ne_pair {
    x : Data<adv> | 2 |, 
    y : (z:Data<adv> | 2 | {z != x}) 
}

def foo() @ alice : Unit = 
    let v : ne_pair = ne_pair(0x1234, 0x5678) in 
    parse v as ne_pair(a, b) in 
    ()
```

More details are given [below](#parsing-structs).

### Singleton Types

A _singleton type_ is a type with exactly one inhabitant. Other than [unit](#unit-and-lemma), Owl uses singleton types pervasively to reason about type refinements. 

#### Const

Given a fixed byte sequence, such as `0x1234`, `Const(0x1234)` is the singleton type for exactly that byte sequence. Such a type is useful to specify tags in TLV formats, for example. Since `0x1234` is a hardcoded constant, this type is a subtype of `Data<static>`. 

#### Name

A _name type_ is a specification for a name, and is part of a name declaration. For example:

```owl
locality alice
name n : nonce @ alice
name k : enckey Name(n) @ alice
```
Here, `nonce` and `enckey Name(n)` are name types. Each name type is in one-to-one correspondence to  a keyed cryptographic primitives. More details are given [here](./crypto.md).

### Exists Types


### If-then-else types

If `p` is a [proposition](#propositions), and `t1` / `t2` are types, then `if p then t1 else t2` is a type. If Owl can prove that `p` holds (or doesn't hold), then this type will automatically simplify to `t1` (respectively, `t2`). 

If-then-else types are most useful for specifying the return types of procedures that depend on whether something is corrupted. For example:

```owl
locality alice
locality bob

name n : nonce
name K : enckey Name(n)

def server (k : Name(K)) @ bob : if sec(K) then Option Name(n) else Option Data<adv> = 
    input i in 
    adec(k, i)
```

The return type of the server states that if the name `K` is a secret, we get a value of type `Option Name(n)` (i.e., a value which is either `None` or `Some(v)`, where `v = get(n)`); if `K` is corrupt, then we get `Option Data<adv>`. This is achieved using [authenticated encryption](./aenc.md).


### Ghost

It is often useful to add information to a data structure that only exists for proof purposes. An example of this is given below:

```owl

name eph : DH @ alice
name n : nonce @ alice 

struct stage2_t {
    recvd_eph_pk : Ghost,
    val : if recvd_eph == dhpk(get(eph)) then  Name(n) else Data<adv>
}
```
Here, we have a pair of two values: the first, which has no runtime representation, represents a received ephemeral public key. 
The second has an [if-then-else type](#if-then-else-types) which states that the `val` is equal to `get(n)` if the ephemeral key is the expected one, and arbitrary junk data otherwise.  


### Grammar of Types
```
t ::=  
    | Data<L>
    | Data<L> |aexpr| 
    | Data<L, |L|> // L : Label
    | Ghost
    | x:t{phi} // phi : Prop
    | Option t
    | s // where s is a struct or enum
    | if prop then t else t
    | Bool<L> // L : Label
    | Unit
    | Name(n) // n : Name
    | vk(n) // n : Name, n must have name type sigkey t for some t
    | dhpk(n) // n : Name, n must have name type DH
    | encpk(n) // n : Name, n must have name type pkekey t
    | shared_secret(n, m) // n, m : Name, must have name type DH
    | exists i. t // binds an index i in t
    | Const(HC) // HC is a hex constant, eg 0x1234
```



## Localities

Localities specify the parties of the protocol. Every compiled name declaration and `def` must be attached to a locality. Localities for a single party are declared simply as 
```owl
locality alice
```
while a _family_ of localities (e.g., specifying a protocol between $n$ servers and clients) are specified with an _arity_, like so:
```owl
locality Server : 1
locality Client : 1
```
Here, the `1` represents the number of _party IDs_ the locality takes as input. For example, we may declare this:
```owl
name n<@j> : nonce @ Server<j> 
```
to mean that each server stores a _single_ name; while this:
```owl
name n<i@j> : nonce @ Server<j>
```
means that each server `Server<j>` stores a family of names `n<i,j>`. Here, `i` is a _session ID_; party IDs and session IDs are detailed in [indices](#indices).


## Indices

To handle protocols with a polynomial number of parties, or a polynomial number of sessions for each party, Owl has a notion of an _index_. Indices can be thought of as type-level numbers (albeit ones that cannot be added, but just passed around). Indices come in three types: _party IDs_, which are used to index a collection of parties (e.g., the `i`th client); _session IDs_, which are used to index within a computation carried out by a single locality (e.g., the `i`th Diffie-Hellman computation done by a particular party); and _ghost indices_, which only have proof content. 

We introduce indices during computations by having index arguments to `def`s:

```owl
locality Server : 1
name n<i@j> : nonce @ Server<j>
def client_main<i@j>(x : Name(n<i@j>)) @ Server<j> : Unit = 
    let y = get(n<i@j>) in 
    assert (x == y);
    ()
```

First, we have a locality with an _arity_ 1, meaning it takes one party ID.
Then, we have the indexed name `n<i@j>`, which takes a session ID `i` and a party ID `j`. (The `@` symbol separates session IDs from party IDs). Index arguments are then introduced after the method name during a `def`. 

Structs and enums can also be indexed:
```owl
locality Server : 1
name n<i@j> : nonce @ Server<j>

struct MyStruct<i,j> {
    v : Name(n<i@j>)
}

def client_main<i@j>(s : MyStruct<session i,pid j>) @ Server<j> : Unit = 
    ()
```

Due to a current design limitation, the syntax for indices is a bit different for structs and enums.  
Indices are introduced into struct declarations without regard for their type (thus, we have `<i,j>` instead of `<i@j>`). When making reference to a struct type (e.g., for `MyStruct`), one must then annotate the index type (hence, we have `MyStruct<session i, pid j>`.)



## Propositions

A _proposition_ is a proof-level property that may be true or false. Propositions in Owl are checked using an SMT solver. We can see them at work here:

```owl
locality alice

def client(x : Data<adv> |2|, y : Data<adv> |2|, z : Data<adv> |2|, w : Data<adv> |2| ) @ alice : Unit = 
    assert (123 == 123);
    assert ((concat(x, y) == concat(z, w)) ==> (x == z));
    ()
```

Assert statements carry propositions, and fail to type check if the SMT solver fails to prove that the proposition is always true. We can see in the second line that the SMT solver can be used to prove nontrivial facts, such as the fact that concatenation is injective (when appropriate side conditions on lengths hold). 

Propositions can show up in [refinement types](#refinement-types), [if-then-else types](#if-then-else-types), [assert/assume expressions](#assertassume), and [pcase expressions](#case-splitting-on-a-proposition), among other places.

### Predicates

A predicate is a [proposition](#propositions)-level macro. An example is below:

```owl
locality alice

predicate ok(v) = 
    (v == 0x1234 \/ v == 0x2345)

def foo(x : (v:Data<adv>{ok[v]})) @ alice : Unit = 
    assert (x != 0x5555);
    ()
```

Predicates do not require type annotations on its arguments, since at the level of propositions, all values are bitstrings. Note that when we apply `ok`, we must use square brackets (such as `ok[v]`); this is a current limitation of the parser. 

### Grammar

```
p ::= // prop
    | True
    | False
    | corr(N) // N : Name. N is corrupt; same as [N] <= adv
    | sec(N) // N : Name. N is secret; same as [N] !<= adv
    | let x = a in p // a : atomic expr
    | a1 == a2 // a1, a2 : atomic expr
    | a1 != a2 // a1, a2 : atomic expr
    | i1 =idx i2 // i1, i2 : index
    | i1 !=idx i2 // i1, i2 : index
    | l1 <= l2 // l1, l2 : label
    | l1 !<= l2 // l1, l2 : label
    | happened(foo<..>(x, y, ..., z)) // foo is a method name; <..> are index parameters (optional); x, y, .., z are arguments (atomic exprs)
    | forall x : idx, y : idx, ..., z : idx. p // x, y, z are identifiers
    | forall x : bv, y : bv, ..., z : bv. p // x, y, z are identifiers
    | aad(N)[a] // N : Name, a : atomic expr
    | in_odh(a, b, c) // a, b, c : atomic expr
    | honest_pk_enc<N>(a) // N : Name, a : atomic expr
    | foo<...>[x, y, .., z] // foo is a predicate; <..> are index  parameters (optional); x, y, .., z are arguments (atomic exprs)
    | a // a : atomic expr. Implicit cast to (a == true)
```

## Expressions

Computations in Owl are carried out by _expressions_. Expressions are stratified into two levels: [_atomic expressions_](#atomic-expressions), which represent pure computations; and _effectful expressions_. Note that in Owl, cryptographic operations are considered effectful. 

### Atomic Expressions

Atomic expressions represent pure computations, and can thus arise up in type-level constructs such as [propositions](#propositions). 

#### Length Constants

When specifying (for example) data formats, it is important to know the length of an encryption key. For this purpose, Owl supports the syntax `|LC|`, where `LC` here is the name for a length constant. For example, type `Data<adv> | |nonce| |` is parsed as follows:

- `Data<adv> | a |` is a type, whenever `a` is an atomic expression;
- `|nonce|` is an atomic expression, since `nonce` is the name for a length constant (which specifies the length of names of type `nonce`).

The supported length constants currently are: 

- `nonce`; for the length of `get(N)` if `N : nonce`;
- `DH`, for the length of `get(N)` if `N : DH`. Note that this is a Diffie-Hellman _secret_ (i.e., exponent), not a group element;
- `enckey`; for the length of `get(N)` if `N : enckey T`;
- `pke_sk`; for the length of `get(N)` if `N : pkekey T`;
- `sigkey`; for the length of `get(N)` if `N : sigkey T`;
- `kdfkey`; for the length of `get(N)` if `N` is a [KDF key](./hkdf.md)
- `mackey`; for the length of `get(N)` if `N : mackey T`;
- `signature`; for the length of the result of [`sign`](./signatures.md);
- `pke_pk`; for the length of `enc_pk(x)` when `x` is a secret key for public-key encryption (i.e., has type `Name(N)` if `N : pkekey T`);
- `vk`; for the length of `vk(x)` when `x` is a signing key (i.e., has type `Name(N)` if `N : sigkey T`);
- `maclen`; for the length of a MAC computed by [`mac`](./mac.md)
- `tag`; for the length of an enum tag (typically one byte);
- `counter`; for the length of a counter, used primarily by [authenticated encryption](./aenc.md);
- `crh`; for the length of a [collision-resistant hash](./crh.md);
- `group`; for the length of a [group element](./hkdf.md). 

#### User-defined functions

In Owl, we can define `func`s, which are atomic expression-level macros. A mininal example is below:

```owl
locality alice

func make_foo(x) = 
    x ++ 0x1234

def foo() @ alice : Unit =
    input i in
    output make_foo(i)
```

#### Grammar

```
a ::= // atomic expr
    | a * a // integer multiplication
    | a ++ a // concatenation
    | a1 &&& a2 // if a1 : Lemma p1, and a2 : Lemma p2, then a1 &&& a2 : Lemma (p1 /\ p2)
    | a1 && a2 // Boolean conjunction
    | a1 + a2  // integer addition
    | !a // Boolean negation
    | () // unit
    | true
    | false 
    | "<alphanum>" // Strings
    | 0x<hexConst> // Hex const; e.g., 0x1234. 0x is the empty hex constant.
    | <natural>    // Integers; e.g., 67. 
    | | LC | // Length constants, where LC is a name of a length constant. 
    | gkdf<nks; j>(a, b, c) // KDF operation in Ghost. nks is a row of name kinds (separated by ||); j is an integer index into this row, and a, b, c are atomic exprs.
    | get(N) // obtain the value of a base name N.
    | get_encpk(N) // obtain the public key for N, if N : Name corresponds to a public encryption key.
    | get_vk(N) // obtain the verification key for N, if N : Name corresponds to a signing key.
    | f<...>(x, y, .., z) // apply function symbol f to arguments x, y, ..., z : atomic expr. Inside <...> are _function parameters_ (used mainly for index arguments to constructors for structs and enums).
    | x // x is a variable
```

### Assert/assume

### Case-Splitting on a Proposition


### Pattern Matching

#### Parsing Structs

#### Case Analysis on Enums

### Debug Expressions

## Declarations

Above, we have seen examples of declaring [names](#labels), methods via `def` (see [here](#labels) and [here](#indices)), [structs and enums](#structs-enums-and-option-types), and [localities](#localities). Below, we outline a number of additional top-level declarations used in Owl protocols.

### Type and Name Type definitions

One can give abbrevations for both types and name types:

```owl
locality alice
locality bob

nametype my_nonce = nonce

name m : my_nonce @ alice 

type my_msg_t = Name(m)

def client(v : my_msg_t) @ alice : Unit = 
    assert (v == get(m));
    ()
```

Name type abbreviations may also carry index arguments:
```owl
locality alice
name m<i> : nonce @ alice

nametype my_key<i> = enckey Name(m<i>)

name k<i> : my_key<i> @ alice

def client<i>(my_k : Name(k<i>)) @ alice : Unit = 
    let c = aenc(my_k, get(m<i>)) in
    ()
```

### Corruption declarations

It is often necessary to restrict the adversary model by asserting that certain names are known to the adversary by default. We do this with a _corruption declaration_, which is as follows:

```owl
locality alice

name n : nonce @ alice
name m : nonce @ alice

corr [n] ==> [m] // If n is corrupt, m is as well
```

All corruption declarations in Owl are hypothetical, and have the form `corr L1 ==> L2`; this emits the axiom that if `L1 <= adv`, then `L2 <= adv`. One can add non-hypothetical corruption axioms by letting the left-hand side be `adv`:

```owl
locality alice

name n : nonce @ alice
corr adv ==> [n]
```

The above constructs a name `n` which Owl trusts is randomly generated, but readable by the adversary. 

Corruption declarations can be indexed:
```owl
locality alice

name n<i> : nonce @ alice 
name m<i> : nonce @ alice 

corr<i> [m<i>] ==> [n<i>]
```

### ODH Declarations

To associate Diffie-Hellman shared secrets with hash permissions, one can use an ODH declaration. More detail is given [here](./hkdf.md).

### Counter Declarations

Owl has a notion of a monotonic counter, which is used primarily for authenticated encryption (but can be used for other purposes). An example is given below:

```owl
locality alice

counter C @ alice

def foo() @ alice : Unit = 
    inc_counter C; // Increments the counter by one
    let x : (v:Data<adv>{length(v) == |counter|}) = get_counter C in 
    ()
```

Counters support two operations: `inc_counter`, which increments it by one; and `get_counter`, which returns the current value of the counter. Owl doesn't currently model that the counter is monotonic, but the fact that we cannot reset or decrement the counter guarantees monotonicity. 
More details are given [here](./aenc.md). 

### Predicate Declarations

Details [here](#predicates).

### Func Declarations

Details [here](#user-defined-functions)





