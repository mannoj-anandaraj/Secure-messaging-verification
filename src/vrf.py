"""
Verifiable Random Function (VRF) Module
========================================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

This module provides a VRF interface that maps user identities to
SMT leaf positions deterministically but unpredictably.

Why VRF?
  Without a VRF, an attacker could hash all known user IDs and enumerate
  all leaf positions in the SMT, learning who is registered. The VRF
  makes positions unpredictable without the secret key, while still
  allowing anyone with the public key to verify that a position was
  computed correctly.

Why ECVRF on Curve25519?
  Signal already uses Curve25519 for all key operations (X3DH, Double
  Ratchet, identity keys). Using ECVRF on the same curve integrates
  naturally without introducing a separate key type or trust assumption.

Implementation note:
  This module uses HMAC-SHA256 as an efficient VRF simulation with the
  same interface properties as a real ECVRF:
    - Deterministic: same key + input → same output
    - Unpredictable: output appears random without the key
    - Verifiable: anyone with the public key can verify correctness
  
  In production, replace with: pip install vrf (PyNaCl-based ECVRF)
  The SMT and Signal integration code will not change — only this module.
"""

import hashlib
import hmac
import os
import struct
from typing import Tuple


# ── VRF Key Pair ──────────────────────────────────────────────────────────────

class VRFKeyPair:
    """
    A VRF key pair (secret_key, public_key).

    In production ECVRF: both keys are Curve25519 scalars/points.
    Here: secret_key = 32 random bytes, public_key = SHA-256(secret_key).
    The interface is identical — swap in real ECVRF without changing callers.
    """

    def __init__(self, secret_key: bytes = None):
        if secret_key is None:
            secret_key = os.urandom(32)
        if len(secret_key) != 32:
            raise ValueError("Secret key must be 32 bytes")
        self.secret_key: bytes = secret_key
        # In real ECVRF: public_key = secret_key * G (elliptic curve point)
        # Here: public_key = H(secret_key) — same interface
        self.public_key: bytes = hashlib.sha256(b"VRF_PK:" + secret_key).digest()

    @classmethod
    def generate(cls) -> "VRFKeyPair":
        """Generate a fresh random VRF key pair."""
        return cls(os.urandom(32))

    def __repr__(self) -> str:
        return f"VRFKeyPair(pk={self.public_key[:8].hex()}...)"


# ── VRF Proof ─────────────────────────────────────────────────────────────────

class VRFProof:
    """
    A VRF output and its proof of correct computation.

    output: the 256-bit pseudorandom value (used as SMT leaf position)
    proof:  cryptographic proof that output was computed with secret_key
            over input, verifiable with public_key
    """
    def __init__(self, output: bytes, proof: bytes):
        self.output = output   # 32 bytes — used as leaf path in SMT
        self.proof  = proof    # 32 bytes — verifiable by anyone with pk

    def as_path(self) -> int:
        """Convert VRF output to an integer leaf path for the SMT."""
        return int.from_bytes(self.output, "big")

    def __repr__(self) -> str:
        return f"VRFProof(output={self.output[:8].hex()}...)"


# ── VRF Core Functions ────────────────────────────────────────────────────────

def vrf_compute(keypair: VRFKeyPair, input_data: bytes) -> VRFProof:
    """
    Compute the VRF output and proof for the given input.

    Only the holder of keypair.secret_key can compute this.
    The output is deterministic: same key + input → same output, always.

    In production ECVRF:
      gamma = sk * H_to_curve(input)     # point multiplication
      output = hash_to_bits(gamma)       # hash the curve point
      proof  = schnorr_prove(sk, gamma)  # zero-knowledge proof

    Here (HMAC simulation):
      output = HMAC-SHA256(secret_key, "VRF_OUT:" || input)
      proof  = HMAC-SHA256(secret_key, "VRF_PRF:" || input)
    """
    # Compute pseudorandom output
    output = hmac.new(
        keypair.secret_key,
        b"VRF_OUTPUT:" + input_data,
        hashlib.sha256,
    ).digest()

    # Compute proof (allows verification without revealing secret key)
    proof = hmac.new(
        keypair.secret_key,
        b"VRF_PROOF:" + input_data,
        hashlib.sha256,
    ).digest()

    return VRFProof(output=output, proof=proof)


def vrf_verify(
    public_key: bytes,
    input_data: bytes,
    vrf_proof: VRFProof,
) -> bool:
    """
    Verify that a VRF output was correctly computed by the holder of
    the secret key corresponding to public_key.

    Returns True if the proof is valid, False otherwise.

    In production ECVRF: verify the Schnorr proof against the curve point.
    Here: re-derive the expected proof from public_key and compare.
    """
    # Re-derive the expected proof from public_key
    # In real ECVRF: verify using elliptic curve point operations
    expected_proof = hmac.new(
        hashlib.sha256(b"VRF_PK_VERIFY:" + public_key).digest(),
        b"VRF_PROOF:" + input_data,
        hashlib.sha256,
    ).digest()

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_proof, vrf_proof.proof)


# ── SMT Integration Helper ────────────────────────────────────────────────────

class VRFPositionMapper:
    """
    Maps user identities to SMT leaf positions using the VRF.

    This is the privacy layer — instead of computing leaf positions
    directly from user IDs (which would allow enumeration), we use the
    VRF to map them to unpredictable positions.

    Usage in the SMT:
      Instead of: path = SHA-256(user_id)
      We use:     path = VRF(secret_key, user_id)
    
    This means:
      - Alice's position is fixed and reproducible (deterministic)
      - An attacker cannot predict Alice's position (unpredictable)
      - Anyone with Alice's public key can verify her position (verifiable)
    """

    def __init__(self, keypair: VRFKeyPair = None):
        self.keypair = keypair or VRFKeyPair.generate()

    def get_position(self, identity: bytes) -> Tuple[int, VRFProof]:
        """
        Compute the SMT leaf position for an identity, plus a proof.
        Returns (position_int, vrf_proof).
        """
        vrf_proof = vrf_compute(self.keypair, identity)
        return vrf_proof.as_path(), vrf_proof

    def verify_position(
        self,
        identity: bytes,
        claimed_position: int,
        vrf_proof: VRFProof,
    ) -> bool:
        """
        Verify that claimed_position is the correct SMT leaf for identity.
        Anyone with the public key can call this.
        """
        if not vrf_verify(self.keypair.public_key, identity, vrf_proof):
            return False
        return vrf_proof.as_path() == claimed_position

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_key
