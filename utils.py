import hashlib
import uuid
import secrets
from datetime import datetime

def generate_did(full_name: str, email: str) -> str:
    """Generate a realistic DID identifier (Simulated Prototype)"""
    seed = f"{full_name}:{email}:{secrets.token_hex(8)}:{datetime.utcnow().timestamp()}"
    hash_hex = hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]
    return f"did:securechain:{hash_hex}"

def generate_nft_id() -> str:
    """Generate a unique NFT-style Asset ID"""
    random_hex = secrets.token_hex(3).upper()
    return f"NFT-2026-{random_hex}"

def generate_tx_hash() -> str:
    """Generate a simulated blockchain transaction hash"""
    return "0x" + secrets.token_hex(32)

def calculate_audit_hash(prev_hash: str, timestamp_str: str, user: str, role: str, action: str, resource: str, status: str, tx_hash: str) -> str:
    """
    Generate SHA-256 hash for audit event hash-chain.
    Ensures tamper-evident integrity of audit records.
    """
    raw_data = f"{prev_hash}|{timestamp_str}|{user}|{role}|{action}|{resource}|{status}|{tx_hash}"
    return hashlib.sha256(raw_data.encode('utf-8')).hexdigest()

def verify_hash_chain(audit_records) -> dict:
    """
    Verifies the integrity of the SHA-256 audit hash chain.
    Returns dict with verification status and details.
    """
    if not audit_records:
        return {"valid": True, "message": "Audit chain is empty. Integrity verified.", "checked_count": 0}
    
    genesis_prev = "GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000000000000000000000000000"
    expected_prev = genesis_prev
    
    for i, record in enumerate(audit_records):
        # record fields: id, timestamp, user, role, action, resource, status, tx_hash, prev_hash, hash
        rec_id = record['id']
        timestamp = record['timestamp']
        user = record['user']
        role = record['role']
        action = record['action']
        resource = record['resource']
        status = record['status']
        tx_hash = record['tx_hash']
        stored_prev = record['prev_hash']
        stored_hash = record['hash']

        # 1. Check previous hash connection
        if i == 0:
            if stored_prev != genesis_prev:
                return {
                    "valid": False,
                    "message": f"Genesis block mismatch at Record #{rec_id}",
                    "failed_record_id": rec_id
                }
        else:
            if stored_prev != expected_prev:
                return {
                    "valid": False,
                    "message": f"Chain link broken at Record #{rec_id}: Previous hash does not match prior block hash.",
                    "failed_record_id": rec_id
                }

        # 2. Re-calculate current hash
        recalculated_hash = calculate_audit_hash(
            stored_prev, timestamp, user, role, action, resource, status, tx_hash
        )

        if recalculated_hash != stored_hash:
            return {
                "valid": False,
                "message": f"Tampering detected at Record #{rec_id}! Data hash does not match stored hash.",
                "failed_record_id": rec_id
            }

        expected_prev = stored_hash

    return {
        "valid": True,
        "message": f"Audit trail integrity verified across all {len(audit_records)} records.",
        "checked_count": len(audit_records)
    }
