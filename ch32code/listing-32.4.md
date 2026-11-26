# Evaluating a new protocol — checklist (v1)

Fill in one copy per protocol. Every answer cites a source: the specification (section),
a paper, an implementation, or a measurement. "Unknown" is an allowed answer; a guess is not.

## 1. Goals
- [ ] What problem does it solve that existing protocols don't? Name the protocol it replaces or extends.
- [ ] Goals written in the five-field form (Ch 3 §3.6): asset, adversary, property, assumptions, out of scope.
- [ ] Which non-goals are stated? Which are silently missing (metadata, availability, deniability)?

## 2. Adversary
- [ ] Network: passive, active (Dolev-Yao), or both?
- [ ] Server / operator: trusted, honest-but-curious, or malicious? For which assets?
- [ ] Endpoint compromise: what is promised before (FS) and after (PCS) a compromise?
- [ ] Quantum: harvest-now-decrypt-later for confidentiality? Live forgery for authentication?

## 3. Properties
- [ ] Each property stated precisely enough to be falsified (Ch 1, Ch 25)
- [ ] Key separation and context binding: what is in the transcript, what labels the KDF uses
- [ ] Downgrade resistance: what is negotiated, and how is the negotiation authenticated?
- [ ] Failure behavior: what happens on a bad message, a lost message, a replay, a crash?

## 4. Analysis
- [ ] Formal analysis exists? Which tool (ProVerif, Tamarin, CryptoVerif, EasyCrypt), which model, which properties?
- [ ] What did the analysis leave out (e.g., implementation, state loss, multi-device)?
- [ ] Independent cryptanalysis and published attacks, with dates and fixes

## 5. Implementations
- [ ] At least two independent implementations? Do they interoperate on shared test vectors?
- [ ] Memory-safe language, constant-time primitives, fuzzed parsers
- [ ] Audits: who, when, scope, published findings
- [ ] Licence compatible with the product

## 6. Deployment experience
- [ ] Deployed at scale? By whom, for how long, on which platforms (including mobile)?
- [ ] Cost on mobile: bytes per message and per handshake, CPU, battery, background limits
- [ ] Operational burden: key rotation, versioning, migration path from what exists today
- [ ] Standardization status (date-stamped): individual draft, WG draft, RFC, or proprietary

## 7. Fit for Murmur
- [ ] Which threats in Fig 31.1 does it change? Which new threats does it add?
- [ ] What would the migration look like (suite, capability, minimum version — Ch 31 §31.4)?
- [ ] Decision: adopt / pilot / watch / reject — with a date to revisit
