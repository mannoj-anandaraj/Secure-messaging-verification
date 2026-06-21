"""
Sparse Merkle Tree (SMT) — Core Implementation
================================================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

Method: Depth-256 Sparse Merkle Tree
- Address space: 2^256 leaf positions
- Supports inclusion proofs AND non-inclusion proofs
- Constant-size proofs: always 256 sibling hashes
- Domain-separated leaf and internal node hashing

Why depth-256?
  SHA-256 produces 256-bit outputs. User identity hashes map exactly
  to leaf positions with no truncation and no collision risk.

References:
  [9] Dowling, Günther, Herath, Stebila — Secure Logging Schemes (2016)
  [8] Dowling & Hale — ACKA: Active MitM Detection (2023)
"""

import hashlib
from typing import Dict, List, Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────

DEPTH = 256  # tree depth = SHA-256 output size in bits

# Domain separators prevent second pre-image attacks
_LEAF_PREFIX     = b"\x00"   # prefix for leaf node hashing
_INTERNAL_PREFIX = b"\x01"   # prefix for internal node hashing
_EMPTY_SEED      = b"SMT_EMPTY_LEAF_v1"


# ── Pre-compute empty subtree hashes ─────────────────────────────────────────
# EMPTY[0] = hash of an empty leaf
# EMPTY[k] = hash of an internal node whose entire subtree is empty at level k
# This is the key optimisation: instead of storing 2^256 empty nodes,
# we pre-compute what those hashes would be.

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _leaf_hash(value: bytes) -> bytes:
    """Hash a leaf value with domain separator."""
    return _sha256(_LEAF_PREFIX + value)

def _node_hash(left: bytes, right: bytes) -> bytes:
    """Hash an internal node with domain separator."""
    return _sha256(_INTERNAL_PREFIX + left + right)

# Build the empty hash table bottom-up
EMPTY: List[bytes] = [_leaf_hash(_EMPTY_SEED)]
for _level in range(DEPTH):
    EMPTY.append(_node_hash(EMPTY[-1], EMPTY[-1]))

# EMPTY[DEPTH] is the hash of a completely empty depth-256 SMT


# ── Proof dataclass ───────────────────────────────────────────────────────────

class SMTProof:
    """
    A proof of membership or non-membership in the SMT.

    siblings: list of 256 sibling hashes, from leaf level up to root.
    is_member: True = inclusion proof, False = non-inclusion proof.
    leaf_hash: the hash stored at the leaf position (empty hash if non-member).
    root: the root hash at time of proof generation.
    key: the key this proof was generated for.
    """
    def __init__(
        self,
        key: bytes,
        is_member: bool,
        leaf_hash: bytes,
        siblings: List[bytes],
        root: bytes,
    ):
        self.key       = key
        self.is_member = is_member
        self.leaf_hash = leaf_hash
        self.siblings  = siblings   # len == DEPTH
        self.root      = root

    def __repr__(self) -> str:
        status = "INCLUSION" if self.is_member else "NON-INCLUSION"
        return (
            f"SMTProof({status}, "
            f"key={self.key[:8].hex()}..., "
            f"root={self.root[:8].hex()}...)"
        )


# ── Sparse Merkle Tree ────────────────────────────────────────────────────────

class SparseMerkleTree:
    """
    Depth-256 Sparse Merkle Tree.

    Stores only non-empty leaves in a dict keyed by their 256-bit path.
    Empty subtrees use precomputed EMPTY hashes — so we never store
    or compute 2^256 nodes.

    Proof size is always exactly 256 hashes (one sibling per level),
    regardless of how many entries are in the tree.
    This constant-size property is essential for per-message key logging
    in Signal's Double Ratchet, where proofs are generated continuously.
    """

    def __init__(self):
        # path (int, 0 to 2^256-1) -> leaf_hash (bytes)
        self._leaves: Dict[int, bytes] = {}
        # path -> original raw value (for retrieval)
        self._values: Dict[int, bytes] = {}
        # current root hash
        self.root: bytes = EMPTY[DEPTH]

    # ── Path derivation ───────────────────────────────────────────────────────

    def _path(self, key: bytes) -> int:
        """
        Map a key to a 256-bit integer leaf path via SHA-256.
        The VRF replaces this in the full system to add privacy.
        """
        return int.from_bytes(_sha256(key), "big")

    # ── Core operations ───────────────────────────────────────────────────────

    def insert(self, key: bytes, value: bytes) -> bytes:
        """
        Insert or update a key-value pair.
        Returns the new root hash.
        """
        path = self._path(key)
        self._leaves[path] = _leaf_hash(value)
        self._values[path] = value
        self.root = self._compute_root()
        return self.root

    def update(self, key: bytes, new_value: bytes) -> bytes:
        """
        Update an existing key with a new value.
        Semantically equivalent to insert — key position is fixed by SHA-256(key).
        Returns the new root hash.
        """
        return self.insert(key, new_value)

    def delete(self, key: bytes) -> bytes:
        """
        Remove a key from the tree.
        Returns the new root hash.
        """
        path = self._path(key)
        self._leaves.pop(path, None)
        self._values.pop(path, None)
        self.root = self._compute_root()
        return self.root

    def get(self, key: bytes) -> Optional[bytes]:
        """Return the raw value stored for key, or None if not present."""
        path = self._path(key)
        return self._values.get(path)

    def contains(self, key: bytes) -> bool:
        """Return True if the key is in the tree."""
        return self._path(key) in self._leaves

    # ── Root computation ──────────────────────────────────────────────────────

    def _compute_root(self) -> bytes:
        """
        Compute the root hash bottom-up from the current set of leaves.

        Only nodes on the path from non-empty leaves to the root are
        computed — everything else uses the pre-computed EMPTY[level] hash.

        Time complexity: O(n * DEPTH) where n = number of non-empty leaves.
        """
        if not self._leaves:
            return EMPTY[DEPTH]

        # Layer 0: non-empty leaves only
        layer: Dict[int, bytes] = dict(self._leaves)

        for level in range(DEPTH):
            next_layer: Dict[int, bytes] = {}
            # Find all parents that have at least one non-empty child
            parents = {path >> 1 for path in layer}
            for parent in parents:
                left  = layer.get(parent << 1,        EMPTY[level])
                right = layer.get((parent << 1) | 1,  EMPTY[level])
                next_layer[parent] = _node_hash(left, right)
            layer = next_layer

        # After DEPTH iterations, layer should contain only the root
        return layer.get(0, EMPTY[DEPTH])

    # ── Proof generation ──────────────────────────────────────────────────────

    def _build_layers(self) -> List[Dict[int, bytes]]:
        """
        Build all tree layers bottom-up, storing only non-empty nodes.
        Used for proof generation.
        """
        layers: List[Dict[int, bytes]] = [dict(self._leaves)]
        layer = dict(self._leaves)

        for level in range(DEPTH):
            next_layer: Dict[int, bytes] = {}
            parents = {path >> 1 for path in layer}
            for parent in parents:
                left  = layer.get(parent << 1,        EMPTY[level])
                right = layer.get((parent << 1) | 1,  EMPTY[level])
                next_layer[parent] = _node_hash(left, right)
            layer = next_layer
            layers.append(dict(layer))

        return layers  # layers[0] = leaves, layers[DEPTH] = {0: root}

    def prove(self, key: bytes) -> SMTProof:
        """
        Generate an inclusion or non-inclusion proof for a key.

        For inclusion:    proves that key maps to a registered value.
        For non-inclusion: proves that key's leaf position is empty.

        Both use the same proof structure — 256 sibling hashes.
        The verifier decides which type based on is_member.
        """
        path = self._path(key)
        layers = self._build_layers()

        siblings: List[bytes] = []
        cur_path = path

        for level in range(DEPTH):
            sibling_path = cur_path ^ 1   # flip the last bit → get sibling
            sibling_hash = layers[level].get(sibling_path, EMPTY[level])
            siblings.append(sibling_hash)
            cur_path >>= 1   # move up to parent

        is_member = path in self._leaves
        leaf = self._leaves.get(path, EMPTY[0])

        return SMTProof(
            key       = key,
            is_member = is_member,
            leaf_hash = leaf,
            siblings  = siblings,
            root      = self.root,
        )

    # ── Proof verification ────────────────────────────────────────────────────

    @staticmethod
    def verify_inclusion(
        key: bytes,
        value: bytes,
        proof: SMTProof,
        expected_root: bytes,
    ) -> bool:
        """
        Verify that key:value IS in the tree that has the given root.

        How it works:
          1. Hash the value to get the leaf hash.
          2. Walk up the tree using sibling hashes from the proof.
          3. Recompute root hash.
          4. If recomputed root == expected_root → proof is valid.
        """
        path = int.from_bytes(_sha256(key), "big")
        current = _leaf_hash(value)
        cur_path = path

        for sibling in proof.siblings:
            if cur_path & 1:   # current node is the RIGHT child
                current = _node_hash(sibling, current)
            else:              # current node is the LEFT child
                current = _node_hash(current, sibling)
            cur_path >>= 1

        return current == expected_root

    @staticmethod
    def verify_non_inclusion(
        key: bytes,
        proof: SMTProof,
        expected_root: bytes,
    ) -> bool:
        """
        Verify that key is NOT in the tree that has the given root.

        How it works:
          Same as verify_inclusion, but we start with EMPTY[0]
          (the hash of an empty leaf) instead of hash(value).
          If this recomputes to expected_root → the position is provably empty.

        This is the property that normal Merkle Trees do NOT support.
        It is the reason SMT was chosen over CONIKS VRF Prefix Tree.
        """
        path = int.from_bytes(_sha256(key), "big")
        current = EMPTY[0]   # empty leaf hash
        cur_path = path

        for sibling in proof.siblings:
            if cur_path & 1:
                current = _node_hash(sibling, current)
            else:
                current = _node_hash(current, sibling)
            cur_path >>= 1

        return current == expected_root

    # ── Utility ───────────────────────────────────────────────────────────────

    def size(self) -> int:
        """Number of registered entries."""
        return len(self._leaves)

    def __repr__(self) -> str:
        return (
            f"SparseMerkleTree("
            f"entries={self.size()}, "
            f"root={self.root[:8].hex()}...)"
        )
