# Verifying Public Key Exchange in Secure Messaging

**MSc Dissertation — King's College London (2025–2026)**  
**Status: 🔬 Active Research / In Progress**

---

## Problem

End-to-end encrypted messaging (Signal, WhatsApp) relies on users trusting
that the public keys they receive actually belong to the intended contact.
An attacker with access to the key distribution server can silently substitute
a victim's public key with their own — a class of attack known as an
**ephemeral key substitution attack** — and intercept all future messages
without detection.

---

## Approach

This dissertation implements a cryptographically verifiable key transparency
layer using two primitives:

| Component | Role |
|---|---|
| **Sparse Merkle Tree (Depth 256)** | Stores the full key history as an authenticated data structure. Any key insertion or change produces a unique root hash, making tampering detectable. |
| **ECVRF (Elliptic Curve Verifiable Random Function)** | Generates a publicly verifiable proof for each key lookup, so users can independently confirm that a returned key is genuine and unmodified. |

---

## Tech Stack

`Python` `PyCryptodome` `PyNaCl`

---

## Repository Structure *(evolving as work progresses)*
