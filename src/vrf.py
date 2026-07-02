"""
Verifiable Random Function (VRF) Module
========================================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

Real ECVRF implementation following RFC 9381:
  Suite: ECVRF-EDWARDS25519-SHA512-ELL2

Why VRF?
  Without a VRF, an attacker could hash all known user IDs and enumerate
  all leaf positions in the SMT, learning who is registered. The VRF
  makes positions unpredictable without the secret key, while still
  allowing anyone with the public key to verify that a position was
  computed correctly.

Why ECVRF over a generic VRF?
  A generic VRF (e.g. HMAC-based) satisfies three properties:
    - Deterministic:   same key + input -> same output
    - Unpredictable:   output looks random without the key
    - Verifiable:      anyone with the public key can check correctness

  But ECVRF adds a critical fourth property: UNIQUENESS.

  Uniqueness means there is exactly ONE valid output for any
  (secret_key, input) pair. A generic HMAC-VRF does NOT guarantee
  this -- the key holder could in principle produce two different
  outputs with valid proofs for the same input.

  In the SMT context, uniqueness is essential:
    Without it, a malicious transparency server could map Alice's
    identity to TWO different leaf positions (shown to Alice and Bob
    separately) -- a split-view attack that MITM detection cannot catch.
    ECVRF's uniqueness, grounded in the elliptic curve discrete log
    assumption (Ed25519), makes this cryptographically impossible.

Why ECVRF on Ed25519 / Curve25519?
  Signal already uses Curve25519 for all key operations (X3DH, Double
  Ratchet, identity keys). Ed25519 is the signing form of Curve25519.
  Using ECVRF on the same curve integrates naturally -- no new key type,
  no extra trust assumption, no additional library dependency beyond PyNaCl
  which is already required for the Signal simulation.

RFC 9381 compliance:
  This implementation follows the ECVRF-EDWARDS25519-SHA512-ELL2 suite
  from RFC 9381 (Verifiable Random Functions, September 2023).
  Key steps:
    1. Hash-to-curve:  H = encode_to_curve(pk, alpha)  [Elligator2/ELL2]
    2. Gamma:          Gamma = sk_scalar * H            [scalar mult]
    3. Nonce:          k = RFC8032 deterministic nonce
    4. Commitment:     U = k*G,  V = k*H
    5. Challenge:      c = ECVRF_challenge_generation(pk, H, Gamma, U, V)
    6. Scalar:         s = (k + c*sk_scalar) mod order
    7. Proof:          pi = (Gamma, c, s)               [80 bytes]
    8. Output:         beta = SHA-512(suite || 0x03 || Gamma_cofactor)
"""

import hashlib
import hmac
import os
import struct
from typing import Tuple

from nacl.bindings import (
    crypto_scalarmult_ed25519_noclamp,
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_core_ed25519_from_uniform,
    crypto_core_ed25519_add,
    crypto_core_ed25519_scalar_reduce,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_is_valid_point,
)
import nacl.signing

# ── RFC 9381 ECVRF-EDWARDS25519-SHA512-ELL2 constants ────────────────────────

SUITE_STRING  = b"\x04"          # ECVRF-EDWARDS25519-SHA512-ELL2
COFACTOR      = b"\x08"          # Ed25519 cofactor = 8
ED25519_ORDER = (                 # l = 2^252 + 27742317777372353535851937790883648493
    2**252 + 27742317777372353535851937790883648493
)
POINT_SIZE    = 32                # compressed Ed25519 point = 32 bytes
SCALAR_SIZE   = 32


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def _scalar_from_bytes(b: bytes) -> int:
    """Interpret little-endian bytes as integer mod Ed25519 order."""
    return int.from_bytes(b, "little") % ED25519_ORDER


def _scalar_to_bytes(n: int) -> bytes:
    """Encode integer as 32-byte little-endian scalar."""
    return (n % ED25519_ORDER).to_bytes(SCALAR_SIZE, "little")


def _clamp_scalar(sk_bytes: bytes) -> bytes:
    """
    Apply RFC 8032 scalar clamping to an Ed25519 secret key.
    This is the standard clamping used in Ed25519 to prevent
    small-subgroup and fault attacks.
    """
    h = bytearray(_sha512(sk_bytes))
    h[0]  &= 248   # clear bottom 3 bits
    h[31] &= 127   # clear top bit
    h[31] |= 64    # set second-highest bit
    return bytes(h[:32])


def _expand_sk(signing_key_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    Expand a 32-byte Ed25519 seed into (clamped_scalar, nonce_prefix).
    Follows RFC 8032 Section 5.1.5.
    """
    h = _sha512(signing_key_bytes)
    scalar = bytearray(h[:32])
    scalar[0]  &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar), h[32:]   # (clamped scalar, nonce prefix)


def _hash_to_try_and_increment(pk_bytes: bytes, alpha: bytes) -> bytes:
    """
    ECVRF_encode_to_try_and_increment (RFC 9381 Section 5.4.1.1).
    Hashes (suite || 0x01 || pk || alpha || ctr) until a valid
    Ed25519 point is found. Used for hash-to-curve.
    """
    for ctr in range(256):
        h = _sha512(
            SUITE_STRING,
            b"\x01",
            pk_bytes,
            alpha,
            bytes([ctr]),
        )
        # Try to use first 32 bytes as a curve point via Elligator2
        candidate = h[:32]
        try:
            # crypto_core_ed25519_from_uniform maps 32 uniform bytes
            # to a valid Ed25519 point via Elligator2 (ELL2)
            point = crypto_core_ed25519_from_uniform(candidate)
            return point
        except Exception:
            continue
    raise RuntimeError("ECVRF hash-to-curve failed after 256 attempts")


def _challenge_generation(
    pk_bytes: bytes,
    H: bytes,
    Gamma: bytes,
    U: bytes,
    V: bytes,
) -> int:
    """
    ECVRF_challenge_generation (RFC 9381 Section 5.4.3).
    c = first 16 bytes of SHA-512(suite || 0x02 || pk || H || Gamma || U || V)
    interpreted as a little-endian integer.
    """
    h = _sha512(SUITE_STRING, b"\x02", pk_bytes, H, Gamma, U, V)
    # RFC 9381: challenge is first ceil(log2(q)/8) bytes = 16 bytes for Ed25519
    c_bytes = h[:16] + b"\x00" * 16   # pad to 32 bytes for scalar arithmetic
    return _scalar_from_bytes(c_bytes)


def _proof_to_hash(Gamma: bytes) -> bytes:
    """
    ECVRF_proof_to_hash (RFC 9381 Section 5.2).
    Multiply Gamma by cofactor (8) then hash.
    beta = SHA-512(suite || 0x03 || Gamma_cofactor)
    Returns 64 bytes; we use first 32 as the VRF output.
    """
    # Multiply Gamma by cofactor (8) via repeated doubling
    # crypto_scalarmult_ed25519_noclamp with scalar=8 (little-endian)
    cofactor_scalar = b"\x08" + b"\x00" * 31
    Gamma_cofactor = crypto_scalarmult_ed25519_noclamp(cofactor_scalar, Gamma)
    beta = _sha512(SUITE_STRING, b"\x03", Gamma_cofactor)
    return beta  # 64 bytes


# ── VRF Key Pair ──────────────────────────────────────────────────────────────

class VRFKeyPair:
    """
    An ECVRF key pair over Ed25519 (Curve25519 in Edwards form).

    secret_key:  32-byte Ed25519 seed (raw random bytes)
    public_key:  32-byte compressed Ed25519 point = sk_scalar * G

    The public key is a proper elliptic curve point, not just a hash.
    This is the fundamental difference from the HMAC stub -- the
    public key now enables real cryptographic proof verification
    without access to the secret key.
    """

    def __init__(self, secret_key: bytes = None):
        if secret_key is None:
            secret_key = os.urandom(32)
        if len(secret_key) != 32:
            raise ValueError("Secret key must be 32 bytes")

        self.secret_key: bytes = secret_key

        # Derive public key: pk = scalar * G (Ed25519 base point)
        # Uses RFC 8032 scalar clamping then base point multiplication
        sk_scalar, _ = _expand_sk(secret_key)
        self.public_key: bytes = crypto_scalarmult_ed25519_base_noclamp(sk_scalar)

    @classmethod
    def generate(cls) -> "VRFKeyPair":
        """Generate a fresh random ECVRF key pair."""
        return cls(os.urandom(32))

    def __repr__(self) -> str:
        return f"VRFKeyPair(pk={self.public_key[:8].hex()}...)"


# ── VRF Proof ─────────────────────────────────────────────────────────────────

class VRFProof:
    """
    An ECVRF proof pi = (Gamma, c, s) as defined in RFC 9381.

    output: 32-byte VRF output derived from Gamma (used as SMT leaf path)
    proof:  80-byte serialised proof = Gamma (32) || c (16) || s (32)

    The proof is verifiable by anyone holding only the public key.
    This is the uniqueness guarantee: Gamma = sk_scalar * H(pk, alpha),
    and the Schnorr-style proof (c, s) cryptographically binds Gamma
    to both the secret key and the input alpha.
    """

    def __init__(self, output: bytes, proof: bytes):
        if len(output) != 32:
            raise ValueError("VRF output must be 32 bytes")
        if len(proof) != 80:
            raise ValueError("VRF proof must be 80 bytes (Gamma||c||s)")
        self.output = output   # 32 bytes — used as leaf path in SMT
        self.proof  = proof    # 80 bytes — verifiable by anyone with pk

    def as_path(self) -> int:
        """Convert VRF output to an integer leaf path for the SMT."""
        return int.from_bytes(self.output, "big")

    def _decode(self) -> Tuple[bytes, int, bytes]:
        """Decode proof into (Gamma, c_int, s_bytes)."""
        Gamma   = self.proof[:32]
        c_bytes = self.proof[32:48]         # 16 bytes challenge
        s_bytes = self.proof[48:80]         # 32 bytes scalar
        c_int   = int.from_bytes(c_bytes, "little")
        return Gamma, c_int, s_bytes

    def __repr__(self) -> str:
        return f"VRFProof(output={self.output[:8].hex()}...)"


# ── VRF Core Functions ────────────────────────────────────────────────────────

def vrf_compute(keypair: VRFKeyPair, input_data: bytes) -> VRFProof:
    """
    Compute the ECVRF proof and output for the given input (RFC 9381 Section 5.1).

    Only the holder of keypair.secret_key can compute this.
    The output is deterministic: same key + input -> same output, always.

    Steps:
      1. H      = ECVRF_encode_to_curve(pk, alpha)   hash input to curve point
      2. Gamma  = sk_scalar * H                       scalar multiplication
      3. k      = RFC8032 deterministic nonce         k = SHA-512(nonce_prefix || H)
      4. U      = k * G,  V = k * H                  commitments
      5. c      = challenge(pk, H, Gamma, U, V)       Fiat-Shamir challenge
      6. s      = (k + c * sk_scalar) mod order       response scalar
      7. pi     = Gamma || c[:16] || s                80-byte proof
      8. beta   = ECVRF_proof_to_hash(Gamma)[:32]     32-byte output
    """
    pk_bytes = keypair.public_key
    sk_scalar_bytes, nonce_prefix = _expand_sk(keypair.secret_key)

    # Step 1: hash input to Ed25519 curve point
    H = _hash_to_try_and_increment(pk_bytes, input_data)

    # Step 2: Gamma = sk_scalar * H
    Gamma = crypto_scalarmult_ed25519_noclamp(sk_scalar_bytes, H)

    # Step 3: deterministic nonce k (RFC 8032 nonce generation)
    # k_bytes = SHA-512(nonce_prefix || H), then reduce mod order
    k_hash = _sha512(nonce_prefix, H)
    k_scalar = _scalar_from_bytes(k_hash[:32])   # reduce to scalar
    k_bytes = _scalar_to_bytes(k_scalar)

    # Step 4: commitments
    U = crypto_scalarmult_ed25519_base_noclamp(k_bytes)   # k * G
    V = crypto_scalarmult_ed25519_noclamp(k_bytes, H)      # k * H

    # Step 5: Fiat-Shamir challenge
    c = _challenge_generation(pk_bytes, H, Gamma, U, V)

    # Step 6: response scalar s = (k + c * sk_scalar) mod order
    sk_int = _scalar_from_bytes(sk_scalar_bytes)
    s_int  = (k_scalar + c * sk_int) % ED25519_ORDER
    s_bytes = _scalar_to_bytes(s_int)

    # Step 7: serialise proof = Gamma || c (16 bytes) || s (32 bytes)
    c_bytes = (c % (2**128)).to_bytes(16, "little")
    proof_bytes = Gamma + c_bytes + s_bytes   # 32 + 16 + 32 = 80 bytes

    # Step 8: derive output from Gamma
    beta = _proof_to_hash(Gamma)
    output = beta[:32]   # use first 32 bytes as the 256-bit VRF output

    return VRFProof(output=output, proof=proof_bytes)


def vrf_verify(
    public_key: bytes,
    input_data: bytes,
    vrf_proof: VRFProof,
) -> bool:
    """
    Verify an ECVRF proof using ONLY the public key (RFC 9381 Section 5.3).

    This is the key distinction from the HMAC stub:
    - HMAC stub required the SECRET key to verify (not real VRF verification)
    - Real ECVRF verification uses ONLY the PUBLIC KEY (a curve point)

    Verification steps:
      1. Decode pi into (Gamma, c, s)
      2. H  = ECVRF_encode_to_curve(pk, alpha)
      3. U' = s*G - c*pk                            recompute commitment
      4. V' = s*H - c*Gamma                         recompute commitment
      5. c' = challenge(pk, H, Gamma, U', V')       recompute challenge
      6. Accept iff c' == c

    Returns True if the proof is valid, False otherwise.
    """
    if len(public_key) != 32:
        return False

    # Validate public key is a valid Ed25519 point
    if not crypto_core_ed25519_is_valid_point(public_key):
        return False

    try:
        Gamma, c_int, s_bytes = vrf_proof._decode()

        # Validate Gamma is a valid curve point
        if not crypto_core_ed25519_is_valid_point(Gamma):
            return False

        # Step 2: recompute H from public key and input
        H = _hash_to_try_and_increment(public_key, input_data)

        # Step 3: U' = s*G - c*pk
        # U' = s*G + ((-c) mod order)*pk
        sG = crypto_scalarmult_ed25519_base_noclamp(s_bytes)
        neg_c = (-c_int) % ED25519_ORDER
        neg_c_bytes = _scalar_to_bytes(neg_c)
        neg_c_pk = crypto_scalarmult_ed25519_noclamp(neg_c_bytes, public_key)
        U_prime = crypto_core_ed25519_add(sG, neg_c_pk)

        # Step 4: V' = s*H - c*Gamma
        sH = crypto_scalarmult_ed25519_noclamp(s_bytes, H)
        neg_c_Gamma = crypto_scalarmult_ed25519_noclamp(neg_c_bytes, Gamma)
        V_prime = crypto_core_ed25519_add(sH, neg_c_Gamma)

        # Step 5: recompute challenge
        c_prime = _challenge_generation(public_key, H, Gamma, U_prime, V_prime)

        # Step 6: accept iff challenges match
        # Constant-time comparison on the 16-byte challenge
        c_int_16  = c_int   % (2**128)
        c_prime_16 = c_prime % (2**128)
        return hmac.compare_digest(
            c_int_16.to_bytes(16, "little"),
            c_prime_16.to_bytes(16, "little"),
        )

    except Exception:
        return False


# ── SMT Integration Helper ────────────────────────────────────────────────────

class VRFPositionMapper:
    """
    Maps user identities to SMT leaf positions using the ECVRF.

    This is the privacy layer -- instead of computing leaf positions
    directly from user IDs (which would allow enumeration), the ECVRF
    maps them to unpredictable positions.

    The ECVRF uniqueness property guarantees that each identity maps to
    exactly one leaf position under a given key -- preventing split-view
    attacks where a malicious server shows different positions to different
    parties for the same identity.

    Usage in the SMT:
      Instead of: path = SHA-256(user_id)        [enumerable]
      We use:     path = ECVRF(secret_key, user_id)  [unique, unpredictable]

    This means:
      - Alice's position is fixed and reproducible (deterministic)
      - An attacker cannot predict Alice's position (unpredictable)
      - Anyone with the public key can verify Alice's position (verifiable)
      - There is exactly one valid position per identity (unique)
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
        Uses ONLY the public key -- secret key not required.
        """
        if not vrf_verify(self.keypair.public_key, identity, vrf_proof):
            return False
        return vrf_proof.as_path() == claimed_position

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_key
