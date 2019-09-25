# A demo project of simple Cryptographic operations
A demo project using Google Tink library for providing simple and secure API
for common cryptographic operations at the application-level, such as:
- symmetric encryption
- message authentication
- digital signatures
- hybrid encryption

<b>Table of Contents:</b>
- [Motivation](#Motivation)
- [Design Consideration](#Design-Consideration)
- [Implementation](#Implementation)
- [References](#References)

<br/>

### <a name="Motivation"></a> Motivation
We take serious consideration in protecting user's data, no matter in-transit
or at-rest. By default we rely on security features provided out-of-the-box
by the platform / vendor product we used, which aligns with latest industry
security standards, so we are ensuring ourselves not building out cryptographic
features from scratch and re-inventing a good old wheel.

```sh
"The history of cryptography shows us that good cryptography has been repeatedly defeated not because of bad math, but because of bad implementations of good math."
```

Yet in certain cases where we must fulfill the requirements from either business
or local regulators, a more stringent security control is needed to further
encrypts the user's data on top of the 3rd party vendor's platform/product,
this is where our in-house cryptographic solution comes into play. For example,
by adding another layer of encryption at the application level, we can isolate
the data from different countries/markets hosted inside a shared persistent
storage facility.

<br/>

### <a name="Design-Consideration"></a> Design Consideration

##### Encryption
The application-level encryption uses AES256 in [Galois/Counter Mode (GCM)](https://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf)
mode, there are 3 reasons:
- AES is widely used because [AES256 is recommended by the National Institute of Standards
and Technology (NIST) for long-term storage use](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
(as of March 2019), and
- AES is often included as part of our integration with 3rd party external systems.
- Galois/Counter Mode (GCM) is a mode of operation for symmetric-key cryptographic block
ciphers that has been widely adopted because of its performance. GCM throughput rates for
state-of-the-art, high-speed communication channels can be achieved with reasonable hardware
resources

<br/>

##### Digitial Signing
The application-level digital signing uses ECDSA, due to following rationale:

- with ECDSA we can get the same level of security as RSA but with smaller keys. Smaller keys are better than larger keys for several reasons.
    - smaller keys have faster algorithms for generating signatures because the math involves smaller numbers,
    - smaller public keys mean smaller certificates and less data to pass around to establish a TLS connection,
    this means quicker connections and faster loading times on websites.
- Bitcoin is a good example of a system that relies on ECDSA for security. Every Bitcoin address is a cryptographic hash of an ECDSA public key.
The ownership of the account is determined by who controls the ECDSA private key.

A 256-bit elliptic curve key provides as much protection as a 3,248-bit asymmetric key. Typical RSA keys in website certificates are 2048-bits. If we compare the portion of the TLS handshake that happens on the server for 256-bit ECDSA keys against the cryptographically much weaker 2048-bit RSA keys, using an ECDSA certificate reduces the cost of the private key operation by a factor of 9.5x, saving a lot of CPU cycles, this had been proved by past analysis from domain expert.

<br/>

##### Cryptographical Library of Choice
We use a common cryptographic library, Google Tink, to implement cryptographic
features consistently across almost the applications. This provides the following
advantages:

- Tink is a cryptographic library that provides a safe, simple and agile API for
common cryptographic tasks, like symmetric encryption, message authentication,
digital signatures, and hybrid encryption.
- Tink provides secure APIs that are easy to use correctly and hard(er) to misuse.
It reduces common crypto pitfalls with user-centered design, careful implementation
and code reviews, and extensive testing. At Google, [AdMob, Android Pay, Google Android Search App](https://www.android.com/pay/)
and several other Google products already use Tink for Java, and a few other projects
are considering Tink adoption.
- Tink offers also key management features and integrates with popular cloud-based
key management systems like [AWS KMS](https://aws.amazon.com/kms/) or [Google Cloud KMS](https://cloud.google.com/kms/).
- Tink is extensible and customizable, allowing us to build upon the core architecture
and key management abilities without having to fork the library.
- Tink is a crypto library written by a group of cryptographers and security
engineers at Google. It was born out of our extensive experience working with
Google's product teams, [fixing weaknesses in implementations](https://github.com/google/wycheproof), and providing
simple APIs that can be used safely without needing a crypto background.

<br/>

### <a name="Implementation"></a> Implementation
The cryptographic feature is built as a wrapper in a common library. It encapsulates
the integration with Google Tink library, and provides the common cryptographic
operations as a set of simple API with a pre-defined algorithm. Such as:

- generate new symmetric key for AES256 GCM encryption/decryption
- encrypt/decrypt the input data with AES256 GCM
- generate new ECDSA keypair for ECDSA P256 digital signing
- sign/verify the input data with ECDSA P256
- generate new symmetric key for HMAC SHA256 128-bit hashing
- computer/verify the hashing with HMAC SHA256 128-bit

The common library can also switch to use other cryptographic library,
for example spring-crypto API. This can easily achieved by creating a
bean that conform to the methods defined through the interface `CryptoClient`.
The idea is to have developers to less worry about the underlying mechanics
to implement a cryptographic feature, they could just use it whenever they
need to encrypt/decrypt certain data,or when they need sign/verify a piece
of data during exchange, and build more secure application.

<br/>

### <a name="References"></a> References
- [Encryption at Rest in Google Cloud Platform](https://cloud.google.com/security/encryption-at-rest/default-encryption/)
- [Google Tink Open Source Project](https://opensource.google.com/projects/tink)
- [Introducing Tink Cryptographic Software](https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html)
- [Tink GitHub Page](https://github.com/google/tink)
- [ECDSA - The digital signature algoritm of a better internet](https://blog.cloudflare.com/ecdsa-the-digital-signature-algorithm-of-a-better-internet/)