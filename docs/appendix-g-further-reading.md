# Appendix G: Further Reading

---

> This is Appendix G of *Murmur* (Volumes 1 and 2), maintained here so it can be updated between printings. Section numbers match the ones the book cites.

This list is for the reader who wants to go past what one book can cover. Every entry is a real, published work: a specification, a peer-reviewed paper (with its venue and year), a book or a course. Where a work exists in both a conference and a journal version, the conference is listed, and the journal version is usually the more complete one. The specifications themselves, with their status, are in Appendix A. This appendix lists only the places to start reading them.

Each section opens with a suggestion of what to read first.

---

## G.1 Primary specifications: where to read them

- **IETF RFCs and drafts:** the RFC Editor (`rfc-editor.org`) for the authoritative text and errata, and the IETF Datatracker (`datatracker.ietf.org`) for drafts and history.
- **Signal Protocol specifications:** `signal.org/docs`. This covers XEdDSA, X3DH, PQXDH, the Double Ratchet, Sesame and ML-KEM Braid.
- **Noise:** `noiseprotocol.org`, which has the specification (revision 34) and lists of implementations.
- **OpenID Foundation:** `openid.net/developers/specs`, for OpenID Connect Core, Discovery and related specifications.
- **W3C Web Authentication:** `w3.org/TR/webauthn-3`. **FIDO Alliance:** `fidoalliance.org/specifications`, for CTAP.
- **NIST:** `csrc.nist.gov`, for FIPS 203–205, the draft of FIPS 206, SP 800-series guidance and IR 8547.
- **CA/Browser Forum:** `cabforum.org`, for the Baseline Requirements.
- **Platforms:** the Android developer documentation (Keystore, key attestation, Network Security Configuration, Play Integrity) and Apple's Platform Security Guide and developer documentation (CryptoKit, Keychain, App Attest, App Transport Security).

## G.2 Foundations: primitives and key derivation

*Start with Rogaway (2002) and Krawczyk (2010).*

- W. Diffie and M. Hellman. "New Directions in Cryptography." *IEEE Transactions on Information Theory*, 1976.
- P. Rogaway. "Authenticated-Encryption with Associated-Data." *ACM CCS*, 2002.
- H. Krawczyk. "Cryptographic Extraction and Key Derivation: The HKDF Scheme." *CRYPTO*, 2010.
- D. J. Bernstein. "Curve25519: New Diffie-Hellman Speed Records." *PKC*, 2006.
- D. J. Bernstein, N. Duif, T. Lange, P. Schwabe and B.-Y. Yang. "High-Speed High-Security Signatures." *CHES*, 2011. (Ed25519.)
- V. T. Hoang, R. Reyhanitabar, P. Rogaway and D. Vizár. "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance." *CRYPTO*, 2015. (The STREAM construction used for attachments.)
- D. Bleichenbacher. "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1." *CRYPTO*, 1998.
- S. Vaudenay. "Security Flaws Induced by CBC Padding: Applications to SSL, IPSEC, WTLS…" *EUROCRYPT*, 2002.
- J. Len, P. Grubbs and T. Ristenpart. "Partitioning Oracle Attacks." *USENIX Security*, 2021. (Why key commitment matters.)
- J. Alwen, B. Blanchet, E. Hauck, E. Kiltz, B. Lipp and D. Riepel. "Analysing the HPKE Standard." *EUROCRYPT*, 2021.

## G.3 Adversaries and threat modeling

*Start with Shostack, then Dolev and Yao.*

- D. Dolev and A. Yao. "On the Security of Public Key Protocols." *IEEE Transactions on Information Theory*, 1983.
- A. Shostack. *Threat Modeling: Designing for Security*. Wiley, 2014.
- K. Cohn-Gordon, C. Cremers and L. Garratt. "On Post-Compromise Security." *IEEE CSF*, 2016.

## G.4 PKI, TLS and mobile transport security

*Start with Georgiev et al. and Fahl et al. (both 2012): they are why Chapter 8 exists.*

- M. Georgiev, S. Iyengar, S. Jana, R. Anubhai, D. Boneh and V. Shmatikov. "The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software." *ACM CCS*, 2012.
- S. Fahl, M. Harbach, T. Muders, L. Baumgärtner, B. Freisleben and M. Smith. "Why Eve and Mallory Love Android: An Analysis of Android SSL (In)Security." *ACM CCS*, 2012.
- B. Laurie. "Certificate Transparency." *Communications of the ACM*, 2014.
- K. Bhargavan, A. Delignat-Lavaud, C. Fournet, A. Pironti and P.-Y. Strub. "Triple Handshakes and Cookie Cutters: Breaking and Fixing Authentication over TLS." *IEEE S&P*, 2014.
- B. Beurdouche, K. Bhargavan, A. Delignat-Lavaud, C. Fournet, M. Kohlweiss, A. Pironti, P.-Y. Strub and J. K. Zinzindohoue. "A Messy State of the Union: Taming the Composite State Machines of TLS." *IEEE S&P*, 2015.
- B. Dowling, M. Fischlin, F. Günther and D. Stebila. "A Cryptographic Analysis of the TLS 1.3 Handshake Protocol Candidates." *ACM CCS*, 2015. (Journal version: *Journal of Cryptology*, 2021.)
- C. Cremers, M. Horvat, J. Hoyland, S. Scott and T. van der Merwe. "A Comprehensive Symbolic Analysis of TLS 1.3." *ACM CCS*, 2017.
- K. Bhargavan, B. Blanchet and N. Kobeissi. "Verified Models and Reference Implementations for the TLS 1.3 Standard Candidate." *IEEE S&P*, 2017.

## G.5 OAuth, OpenID Connect and authentication

*Start with Fett, Küsters and Schmitz (2016).*

- D. Fett, R. Küsters and G. Schmitz. "A Comprehensive Formal Security Analysis of OAuth 2.0." *ACM CCS*, 2016.
- D. Fett, R. Küsters and G. Schmitz. "The Web SSO Standard OpenID Connect: In-Depth Formal Security Analysis and Security Guidelines." *IEEE CSF*, 2017.
- J. Richer and A. Sanso. *OAuth 2 in Action*. Manning, 2017.

## G.6 Authenticated key exchange and Noise

*Start with Krawczyk's SIGMA paper.*

- R. Canetti and H. Krawczyk. "Analysis of Key-Exchange Protocols and Their Use for Building Secure Channels." *EUROCRYPT*, 2001.
- H. Krawczyk. "SIGMA: The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE Protocols." *CRYPTO*, 2003.
- H. Krawczyk. "HMQV: A High-Performance Secure Diffie-Hellman Protocol." *CRYPTO*, 2005.
- T. Perrin. *The Noise Protocol Framework*, revision 34, 2018.
- N. Kobeissi, G. Nicolas and K. Bhargavan. "Noise Explorer: Fully Automated Modeling and Verification for Arbitrary Noise Protocols." *IEEE EuroS&P*, 2019.

## G.7 Signal Protocol, ratchets and post-quantum messaging

*Start with Cohn-Gordon et al. (2017), then the SPQR announcement.*

- K. Cohn-Gordon, C. Cremers, B. Dowling, L. Garratt and D. Stebila. "A Formal Security Analysis of the Signal Messaging Protocol." *IEEE EuroS&P*, 2017. (Journal version: *Journal of Cryptology*, 2020.)
- J. Alwen, S. Coretti and Y. Dodis. "The Double Ratchet: Security Notions, Proofs, and Modularization for the Signal Protocol." *EUROCRYPT*, 2019.
- N. Unger, S. Dechand, J. Bonneau, S. Fahl, H. Perl, I. Goldberg and M. Smith. "SoK: Secure Messaging." *IEEE S&P*, 2015.
- K. Bhargavan, C. Jacomme, F. Kiefer and R. Schmidt. "Formal Verification of the PQXDH Post-Quantum Key Agreement Protocol for End-to-End Secure Messaging." *USENIX Security*, 2024.
- G. Connell and R. Schmidt. "Signal Protocol and Post-Quantum Ratchets." Signal blog, October 2025. It links the Eurocrypt 2025 and USENIX Security 2025 papers behind SPQR, including B. Auerbach, Y. Dodis, D. Jost, S. Katsumata, T. Prest and R. Schmidt, "Migrating Protocols to the Post-Quantum Setting: The Case of Signal's Double Ratchet."
- V. Cheval and C. Jacomme. "Automated Formal Analysis of Signal's Double Ratchet: Attacks, Fixes and Security Proofs." Preprint, 2026.
- I. Martiny, G. Kaptchuk, A. Aviv, D. Roche and E. Wustrow. "Improving Signal's Sealed Sender." *NDSS*, 2021.
- Apple Security Engineering and Architecture. "iMessage with PQ3: The New State of the Art in Quantum-Secure Messaging at Scale." Apple Security Research blog, 2024.

## G.8 Multi-device identity and key transparency

*Start with CONIKS.*

- M. Melara, A. Blankstein, J. Bonneau, E. Felten and M. Freedman. "CONIKS: Bringing Key Transparency to End Users." *USENIX Security*, 2015.
- M. Chase, A. Deshpande, E. Ghosh and H. Malvai. "SEEMless: Secure End-to-End Encrypted Messaging with less Trust." *ACM CCS*, 2019.
- The IETF KEYTRANS architecture and protocol drafts (Appendix A), for the design converging toward a standard.

## G.9 Group messaging and MLS

*Start with the MLS architecture (RFC 9750), then Alwen et al. (2020).*

- P. Rösler, C. Mainka and J. Schwenk. "More is Less: On the End-to-End Security of Group Chats in Signal, WhatsApp, and Threema." *IEEE EuroS&P*, 2018.
- K. Bhargavan, R. Barnes and E. Rescorla. "TreeKEM: Asynchronous Decentralized Key Management for Large Dynamic Groups." Inria research report, 2018.
- J. Alwen, S. Coretti, Y. Dodis and Y. Tselekounis. "Security Analysis and Improvements for the IETF MLS Standard for Group Messaging." *CRYPTO*, 2020.

## G.10 Metadata and privacy

- A. Davidson, I. Goldberg, N. Sullivan, G. Tankersley and F. Valsorda. "Privacy Pass: Bypassing Internet Challenges Anonymously." *Proceedings on Privacy Enhancing Technologies (PETS)*, 2018.
- RFC 9458 (Oblivious HTTP) and RFC 9849 (Encrypted Client Hello): see their security and privacy considerations sections, which are unusually readable.

## G.11 Post-quantum cryptography and migration

*Start with Mosca (2018) and NIST IR 8547.*

- P. W. Shor. "Algorithms for Quantum Computation: Discrete Logarithms and Factoring." *IEEE FOCS*, 1994.
- M. Mosca. "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?" *IEEE Security & Privacy*, 2018.
- C. Gidney. "How to Factor 2048 Bit RSA Integers with Less than a Million Noisy Qubits." arXiv:2505.15917, 2025.
- NIST. FIPS 203, 204 and 205 (2024), and NIST IR 8547, *Transition to Post-Quantum Cryptography Standards* (final, 2026).

## G.12 Testing, verification and implementation security

*Start with Project Wycheproof; it turns this book's warnings into test cases.*

- B. Blanchet. "Modeling and Verifying Security Protocols with the Applied Pi Calculus and ProVerif." *Foundations and Trends in Privacy and Security*, 2016.
- S. Meier, B. Schmidt, C. Cremers and D. Basin. "The TAMARIN Prover for the Symbolic Analysis of Security Protocols." *CAV*, 2013.
- Project Wycheproof (C2SP): test vectors for known pitfalls in common cryptographic algorithms.
- OWASP. *Mobile Application Security Verification Standard (MASVS)* and *Mobile Application Security Testing Guide (MASTG)*: the community baseline for mobile app security testing.

## G.13 Books

- D. Boneh and V. Shoup. *A Graduate Course in Applied Cryptography*. Free online, regularly revised. Rigorous and complete.
- J. Katz and Y. Lindell. *Introduction to Modern Cryptography*, 3rd edition. CRC Press, 2020.
- J.-P. Aumasson. *Serious Cryptography*, 2nd edition. No Starch Press, 2024.
- D. Wong. *Real-World Cryptography*. Manning, 2021.
- I. Ristić. *Bulletproof TLS and PKI*, 2nd edition. Feisty Duck, 2022.
- N. Ferguson, B. Schneier and T. Kohno. *Cryptography Engineering*. Wiley, 2010.
- R. Anderson. *Security Engineering*, 3rd edition. Wiley, 2020.

## G.14 Courses

- D. Boneh. *Cryptography I*. Stanford University, on Coursera: the standard introductory course.
- The IETF's working-group meeting recordings (TLS, OAuth, MLS, KEYTRANS, MIMI, PQUIP): the fastest way to learn why a design ended up as it did.

