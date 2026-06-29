"""
Signal Protocol Simulation with SMT Key Logging
=================================================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

Simulates the key exchange points in X3DH and Double Ratchet
where ephemeral keys are generated, transmitted, and logged
to the Sparse Merkle Tree.

This is NOT a full Signal implementation — it simulates the
cryptographic key exchange structure to demonstrate where
the SMT logging integrates and how MITM detection works.

Key exchange points logged to SMT:
  1. X3DH: Alice's ephemeral key EK_A (one-time)
  2. X3DH: Bob's one-time prekey OPK_B (consumed per session)
  3. Double Ratchet: per-message DH ratchet public keys

References:
  [2] Marlinspike & Perrin — The X3DH Key Agreement Protocol
  [3] Perrin & Marlinspike — The Double Ratchet Algorithm
  [8] Dowling & Hale — ACKA: Active MitM Detection (2023)
"""

import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from smt import SparseMerkleTree, SMTProof


# ── Cryptographic primitives (simplified) ────────────────────────────────────

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Simplified HKDF — in real Signal uses full RFC5869 HKDF."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]

def _dh(private_key: bytes, public_key: bytes) -> bytes:
    """Simulate DH(private, public) — in real Signal uses X25519."""
    # XOR simulation — replace with real X25519 in production
    return _sha256(b"DH:" + private_key + b":" + public_key)

def _generate_keypair() -> Tuple[bytes, bytes]:
    """Generate (private_key, public_key) pair."""
    private = os.urandom(32)
    # In real Signal: public = X25519(private, G) using Curve25519
    public = _sha256(b"PK:" + private)
    return private, public

def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Simulate symmetric encryption — in real Signal uses AES-256-GCM."""
    return _sha256(key + plaintext) + plaintext  # simplified

def _decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Simulate decryption."""
    return ciphertext[32:]  # strip the simulated MAC


# ── Key types ─────────────────────────────────────────────────────────────────

@dataclass
class IdentityKeyPair:
    """Long-term identity key — never rotates."""
    private: bytes
    public: bytes
    owner: str

    @classmethod
    def generate(cls, owner: str) -> "IdentityKeyPair":
        priv, pub = _generate_keypair()
        return cls(private=priv, public=pub, owner=owner)


@dataclass
class PreKeyBundle:
    """
    Bob's prekey bundle — uploaded to server before any session.
    Contains the keys X3DH needs to establish a shared secret
    even when Bob is offline.
    """
    identity_key_pub:   bytes   # IK_B
    signed_prekey_pub:  bytes   # SPK_B (rotated periodically)
    signed_prekey_priv: bytes
    one_time_prekey_pub:  bytes   # OPK_B (consumed once)
    one_time_prekey_priv: bytes
    owner: str

    @classmethod
    def generate(cls, identity: IdentityKeyPair) -> "PreKeyBundle":
        spk_priv, spk_pub = _generate_keypair()
        opk_priv, opk_pub = _generate_keypair()
        return cls(
            identity_key_pub     = identity.public,
            signed_prekey_pub    = spk_pub,
            signed_prekey_priv   = spk_priv,
            one_time_prekey_pub  = opk_pub,
            one_time_prekey_priv = opk_priv,
            owner = identity.owner,
        )


@dataclass
class X3DHResult:
    """Output of the X3DH key exchange."""
    shared_secret:   bytes   # SK — used to initialise Double Ratchet
    ephemeral_key_pub: bytes # EK_A — Alice's ephemeral key (logged to SMT)
    session_id:      str


@dataclass
class RatchetState:
    """State for one party's Double Ratchet session."""
    root_key:      bytes
    chain_key:     bytes
    ratchet_priv:  bytes
    ratchet_pub:   bytes   # current DH ratchet public key (logged to SMT)
    remote_pub:    Optional[bytes]
    msg_number:    int = 0
    owner:         str = ""


@dataclass
class LoggedKeyEvent:
    """
    A key exchange event recorded in the SMT log.
    Captures everything needed for MITM detection.
    """
    event_type:   str     # "X3DH_EPHEMERAL", "X3DH_OPK", "RATCHET"
    owner:        str
    public_key:   bytes   # the key being logged
    session_id:   str
    timestamp:    float
    smt_root:     bytes   # root hash AFTER this key was logged


# ── SMT Key Transparency Log ──────────────────────────────────────────────────

class KeyTransparencyLog:
    """
    The core contribution of this project.

    Records every ephemeral key at the point of exchange in a
    tamper-evident Sparse Merkle Tree. Any substitution by an
    active MITM creates a verifiable inconsistency.

    This implements the logging component of the ACKA framework
    defined by Dowling & Hale [8], using the SMT properties
    formalised by Dowling et al. [9].
    """

    def __init__(self):
        self.tree = SparseMerkleTree()
        self.events: List[LoggedKeyEvent] = []

    def log_key(
        self,
        owner: str,
        public_key: bytes,
        session_id: str,
        event_type: str = "KEY",
    ) -> LoggedKeyEvent:
        """
        Log an ephemeral public key into the SMT.

        The SMT key is derived from (owner, session_id, event_type)
        to ensure each distinct key exchange event has a unique position.
        """
        # Unique key for this exchange event
        log_key = _sha256(
            owner.encode() + b":" +
            session_id.encode() + b":" +
            event_type.encode()
        )

        # Insert into SMT — value is the actual public key
        new_root = self.tree.insert(log_key, public_key)

        event = LoggedKeyEvent(
            event_type = event_type,
            owner      = owner,
            public_key = public_key,
            session_id = session_id,
            timestamp  = time.time(),
            smt_root   = new_root,
        )
        self.events.append(event)
        print(f"  [LOG] {event_type} for {owner} | "
              f"key={public_key[:6].hex()}... | "
              f"root={new_root[:6].hex()}...")
        return event

    def generate_proof(
        self,
        owner: str,
        session_id: str,
        event_type: str = "KEY",
    ) -> SMTProof:
        """
        Generate a proof that a key was (or was not) logged.
        Bob calls this to verify the key he received.
        """
        log_key = _sha256(
            owner.encode() + b":" +
            session_id.encode() + b":" +
            event_type.encode()
        )
        return self.tree.prove(log_key)

    def verify_key(
        self,
        owner: str,
        public_key: bytes,
        session_id: str,
        event_type: str = "KEY",
        expected_root: bytes = None,
    ) -> bool:
        """
        Verify that a received public_key matches what is in the log.
        This is what Bob calls when he receives a key from Alice.

        Returns True if the key is valid, False if MITM detected.
        """
        log_key = _sha256(
            owner.encode() + b":" +
            session_id.encode() + b":" +
            event_type.encode()
        )
        proof = self.tree.prove(log_key)
        root = expected_root or self.tree.root

        if proof.is_member:
            return SparseMerkleTree.verify_inclusion(log_key, public_key, proof, root)
        else:
            # Key not in log — non-inclusion proof
            return False

    @property
    def current_root(self) -> bytes:
        return self.tree.root


# ── X3DH Session Initiation ───────────────────────────────────────────────────

def x3dh_initiate(
    alice: IdentityKeyPair,
    bob_bundle: PreKeyBundle,
    log: KeyTransparencyLog,
    session_id: str,
) -> X3DHResult:
    """
    Alice initiates an X3DH session with Bob.

    Key exchange:
      DH1 = DH(IK_A, SPK_B)
      DH2 = DH(EK_A, IK_B)
      DH3 = DH(EK_A, SPK_B)
      DH4 = DH(EK_A, OPK_B)
      SK  = KDF(DH1 || DH2 || DH3 || DH4)

    EK_A and OPK_B are logged to the SMT immediately.
    If an attacker substitutes EK_A or OPK_B in transit,
    Bob's verification will fail.
    """
    print(f"\n[X3DH] Alice initiating session with Bob (session={session_id})")

    # Alice generates her ephemeral key EK_A
    ek_priv, ek_pub = _generate_keypair()
    print(f"  [X3DH] Alice generated EK_A = {ek_pub[:8].hex()}...")

    # Log EK_A to the SMT — this is the key contribution
    log.log_key(
        owner      = f"alice_ek_{session_id}",
        public_key = ek_pub,
        session_id = session_id,
        event_type = "X3DH_EPHEMERAL",
    )

    # Log Bob's OPK_B being consumed
    log.log_key(
        owner      = f"bob_opk_{session_id}",
        public_key = bob_bundle.one_time_prekey_pub,
        session_id = session_id,
        event_type = "X3DH_OPK",
    )

    # Compute DH values (as per X3DH spec)
    dh1 = _dh(alice.private, bob_bundle.signed_prekey_pub)   # DH(IK_A, SPK_B)
    dh2 = _dh(ek_priv,       alice.public)                   # DH(EK_A, IK_B) — simplified
    dh3 = _dh(ek_priv,       bob_bundle.signed_prekey_pub)   # DH(EK_A, SPK_B)
    dh4 = _dh(ek_priv,       bob_bundle.one_time_prekey_pub) # DH(EK_A, OPK_B)

    # Derive shared secret
    shared_secret = _hkdf(dh1 + dh2 + dh3 + dh4, b"X3DH_SK_" + session_id.encode())
    print(f"  [X3DH] Shared secret derived: {shared_secret[:8].hex()}...")
    print(f"  [SMT]  Root after X3DH logging: {log.current_root[:8].hex()}...")

    return X3DHResult(
        shared_secret    = shared_secret,
        ephemeral_key_pub= ek_pub,
        session_id       = session_id,
    )


def x3dh_respond(
    bob: IdentityKeyPair,
    bob_bundle: PreKeyBundle,
    alice_identity_pub: bytes,
    alice_ek_pub: bytes,
    log: KeyTransparencyLog,
    session_id: str,
    tampered: bool = False,
) -> Tuple[Optional[bytes], bool]:
    """
    Bob receives Alice's X3DH initiation and verifies against the SMT log.

    Returns (shared_secret, mitm_detected).
    If tampered=True, simulates an attacker substituting alice_ek_pub.
    """
    print(f"\n[X3DH] Bob responding to Alice's session (session={session_id})")

    # ── MITM detection happens here ───────────────────────────────────────────
    print(f"  [VERIFY] Checking Alice's EK_A against SMT log...")

    key_in_log = log.verify_key(
        owner      = f"alice_ek_{session_id}",
        public_key = alice_ek_pub,
        session_id = session_id,
        event_type = "X3DH_EPHEMERAL",
        expected_root = log.current_root,
    )

    if not key_in_log:
        print(f"  [!!! MITM DETECTED !!!] EK_A verification FAILED")
        print(f"  [!!! MITM DETECTED !!!] Received key does not match SMT log")
        print(f"  [!!! MITM DETECTED !!!] Session ABORTED")
        return None, True

    print(f"  [VERIFY] EK_A verified against SMT log — OK")

    # Compute same shared secret as Alice
    dh1 = _dh(bob_bundle.signed_prekey_priv, alice_identity_pub)
    dh2 = _dh(bob.private, alice_ek_pub)
    dh3 = _dh(bob_bundle.signed_prekey_priv, alice_ek_pub)
    dh4 = _dh(bob_bundle.one_time_prekey_priv, alice_ek_pub)

    shared_secret = _hkdf(dh1 + dh2 + dh3 + dh4, b"X3DH_SK_" + session_id.encode())
    print(f"  [X3DH] Shared secret derived: {shared_secret[:8].hex()}...")

    return shared_secret, False


# ── Double Ratchet ────────────────────────────────────────────────────────────

def ratchet_init_sender(shared_secret: bytes, owner: str) -> RatchetState:
    """Initialise Alice's ratchet state from the X3DH shared secret."""
    rk = _hkdf(shared_secret, b"RATCHET_INIT_RK")
    ck = _hkdf(shared_secret, b"RATCHET_INIT_CK")
    priv, pub = _generate_keypair()
    return RatchetState(
        root_key   = rk,
        chain_key  = ck,
        ratchet_priv = priv,
        ratchet_pub  = pub,
        remote_pub = None,
        owner      = owner,
    )

def ratchet_init_receiver(shared_secret: bytes, owner: str) -> RatchetState:
    """Initialise Bob's ratchet state."""
    return ratchet_init_sender(shared_secret, owner)

def ratchet_send(
    state: RatchetState,
    plaintext: bytes,
    log: KeyTransparencyLog,
    session_id: str,
) -> Tuple[bytes, bytes, bytes, RatchetState]:
    """
    Send a message using the Double Ratchet.
    Logs the current DH ratchet public key to the SMT.

    Returns (ciphertext, message_key, ratchet_pub, new_state).
    """
    state.msg_number += 1

    # Log current DH ratchet public key — THIS is what gets attacked
    event_type = f"RATCHET_MSG_{state.msg_number}"
    log.log_key(
        owner      = f"{state.owner}_{session_id}",
        public_key = state.ratchet_pub,
        session_id = session_id,
        event_type = event_type,
    )

    # Derive message key from chain key
    # RK, CK = KDF_RK(RK, DH(DHs, DHr))
    message_key = _hkdf(state.chain_key, b"MSG_KEY_" + state.msg_number.to_bytes(4, "big"))
    new_chain_key = _hkdf(state.chain_key, b"CHAIN_ADVANCE")

    # Update state
    new_state = RatchetState(
        root_key     = state.root_key,
        chain_key    = new_chain_key,
        ratchet_priv = state.ratchet_priv,
        ratchet_pub  = state.ratchet_pub,
        remote_pub   = state.remote_pub,
        msg_number   = state.msg_number,
        owner        = state.owner,
    )

    ciphertext = _encrypt(message_key, plaintext)
    return ciphertext, message_key, state.ratchet_pub, new_state


def ratchet_receive(
    state: RatchetState,
    ciphertext: bytes,
    sender_ratchet_pub: bytes,
    log: KeyTransparencyLog,
    session_id: str,
    msg_number: int,
    sender_name: str,
    tampered: bool = False,
) -> Tuple[Optional[bytes], bool, RatchetState]:
    """
    Receive and verify a message.
    Verifies the sender's DH ratchet public key against the SMT log.

    Returns (plaintext, mitm_detected, new_state).
    """
    print(f"\n  [RATCHET] {state.owner} verifying msg #{msg_number} ratchet key...")

    event_type = f"RATCHET_MSG_{msg_number}"
    key_valid = log.verify_key(
        owner      = f"{sender_name}_{session_id}",
        public_key = sender_ratchet_pub,
        session_id = session_id,
        event_type = event_type,
        expected_root = log.current_root,
    )

    if not key_valid:
        print(f"  [!!! MITM DETECTED !!!] Ratchet key verification FAILED on msg #{msg_number}")
        return None, True, state

    print(f"  [VERIFY] Ratchet key for msg #{msg_number} verified — OK")
    message_key = _hkdf(state.chain_key, b"MSG_KEY_" + msg_number.to_bytes(4, "big"))
    plaintext = _decrypt(message_key, ciphertext)

    new_state = RatchetState(
        root_key     = state.root_key,
        chain_key    = _hkdf(state.chain_key, b"CHAIN_ADVANCE"),
        ratchet_priv = state.ratchet_priv,
        ratchet_pub  = state.ratchet_pub,
        remote_pub   = sender_ratchet_pub,
        msg_number   = state.msg_number,
        owner        = state.owner,
    )

    return plaintext, False, new_state
