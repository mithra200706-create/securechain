import sqlite3
import os
from werkzeug.security import generate_password_hash
from utils import generate_did, generate_nft_id, generate_tx_hash, calculate_audit_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'securechain.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # Identities Table (DID)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS identities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        did TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        organization TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT DEFAULT 'VERIFIED',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # Assets Table (NFT)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nft_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        asset_type TEXT NOT NULL,
        description TEXT,
        current_owner TEXT NOT NULL,
        original_owner TEXT NOT NULL,
        value_ref TEXT,
        tx_hash TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # Ownership History Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ownership_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_nft_id TEXT NOT NULL,
        asset_name TEXT NOT NULL,
        previous_owner TEXT NOT NULL,
        new_owner TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # Access Requests Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS access_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        asset_nft_id TEXT NOT NULL,
        asset_name TEXT NOT NULL,
        permission_requested TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'Pending',
        reviewed_by TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # Audit Logs Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        user TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        status TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
    );
    ''')

    conn.commit()

    # Seed data if empty
    cursor.execute('SELECT COUNT(*) as count FROM users')
    if cursor.fetchone()['count'] == 0:
        seed_data(conn)

    conn.close()

def log_audit_event(conn, user, role, action, resource, status, tx_hash=None):
    """Inserts a tamper-evident audit log into the hash chain."""
    if not tx_hash:
        tx_hash = generate_tx_hash()
    
    cursor = conn.cursor()
    cursor.execute('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1')
    last_row = cursor.fetchone()
    
    genesis_prev = "GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000000000000000000000000000"
    prev_hash = last_row['hash'] if last_row else genesis_prev
    
    timestamp_str = sqlite3.datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    
    curr_hash = calculate_audit_hash(prev_hash, timestamp_str, user, role, action, resource, status, tx_hash)
    
    cursor.execute('''
        INSERT INTO audit_logs (timestamp, user, role, action, resource, status, tx_hash, prev_hash, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp_str, user, role, action, resource, status, tx_hash, prev_hash, curr_hash))
    conn.commit()
    return tx_hash, curr_hash

def seed_data(conn):
    cursor = conn.cursor()

    # 1. Seed Users
    users_data = [
        ('admin', generate_password_hash('admin123'), 'Admin', 'Alexander Vance (Admin)', 'admin@securechain.io'),
        ('manager', generate_password_hash('manager123'), 'Manager', 'Dr. Sarah Connor (Manager)', 'manager@securechain.io'),
        ('auditor', generate_password_hash('auditor123'), 'Auditor', 'Marcus Brody (Auditor)', 'auditor@securechain.io'),
        ('user', generate_password_hash('user123'), 'User', 'Elena Rostova (User)', 'user@securechain.io')
    ]
    for u in users_data:
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, full_name, email)
            VALUES (?, ?, ?, ?, ?)
        ''', u)

    # 2. Seed Identities (12 Identities)
    identities_data = [
        (generate_did('Alexander Vance', 'admin@securechain.io'), 'Alexander Vance', 'admin@securechain.io', 'SecureChain Core', 'Admin', 'VERIFIED'),
        (generate_did('Dr. Sarah Connor', 'manager@securechain.io'), 'Dr. Sarah Connor', 'manager@securechain.io', 'Asset Operations', 'Manager', 'VERIFIED'),
        (generate_did('Marcus Brody', 'auditor@securechain.io'), 'Marcus Brody', 'auditor@securechain.io', 'Global Security Audit', 'Auditor', 'VERIFIED'),
        (generate_did('Elena Rostova', 'user@securechain.io'), 'Elena Rostova', 'user@securechain.io', 'Research Wing', 'User', 'VERIFIED'),
        (generate_did('Viktor Vance', 'viktor@cyber.gov'), 'Viktor Vance', 'viktor@cyber.gov', 'GovSec Cyber Defense', 'Manager', 'VERIFIED'),
        (generate_did('Aisha Patel', 'aisha@techshield.org'), 'Aisha Patel', 'aisha@techshield.org', 'TechShield Solutions', 'User', 'VERIFIED'),
        (generate_did('David Sterling', 'dsterling@fintech.io'), 'David Sterling', 'dsterling@fintech.io', 'FinTech Trust Labs', 'Auditor', 'VERIFIED'),
        (generate_did('Prof. Robert Langdon', 'langdon@harvard.edu'), 'Prof. Robert Langdon', 'langdon@harvard.edu', 'Symbology Research', 'User', 'VERIFIED'),
        (generate_did('Claire Bennet', 'claire@primatech.org'), 'Claire Bennet', 'claire@primatech.org', 'Bio-Security Tech', 'User', 'PENDING'),
        (generate_did('Hiro Nakamura', 'hiro@futurenet.jp'), 'Hiro Nakamura', 'hiro@futurenet.jp', 'Chronos Protocol', 'Manager', 'VERIFIED'),
        (generate_did('Gabriel Gray', 'sylar@apex.com'), 'Gabriel Gray', 'sylar@apex.com', 'Apex Infrastructure', 'User', 'REVOKED'),
        (generate_did('Samantha Carter', 'sg1@stargate.mil'), 'Samantha Carter', 'sg1@stargate.mil', 'Department of Defense', 'Admin', 'VERIFIED')
    ]
    for id_rec in identities_data:
        cursor.execute('''
            INSERT INTO identities (did, full_name, email, organization, role, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', id_rec)

    # 3. Seed Assets (8 Assets)
    assets_data = [
        ('NFT-2026-8F92A1', 'Sovereign Digital Identity Contract', 'Digital Document', 'Core smart contract blueprint for Decentralized Identity verification.', 'Alexander Vance (Admin)', 'Alexander Vance (Admin)', 'REF-DOC-2026-001', generate_tx_hash(), 'ACTIVE'),
        ('NFT-2026-9C41B3', 'Quantum Key Infrastructure Specs', 'Equipment', 'Hardware security module allocation and lattice cryptography key specs.', 'Dr. Sarah Connor (Manager)', 'Alexander Vance (Admin)', 'REF-EQ-9844-QK', generate_tx_hash(), 'ACTIVE'),
        ('NFT-2026-1E77A8', 'National Cyber Defense License 2026', 'License', 'Federal license authorizing secure cryptographic asset clearance.', 'Dr. Sarah Connor (Manager)', 'GovSec Cyber Defense', 'REF-LIC-88219', generate_tx_hash(), 'ACTIVE'),
        ('NFT-2026-4B12F9', 'Zero-Knowledge Audit Trail Schema', 'Certificate', 'Mathematical proof of non-interactive zero-knowledge log integrity.', 'Marcus Brody (Auditor)', 'Marcus Brody (Auditor)', 'REF-CERT-ZKP-09', generate_tx_hash(), 'ACTIVE'),
        ('NFT-2026-3D88E2', 'Satellite Communications Encryption Key', 'Government Record', 'Top level orbital satellite relay key assignment document.', 'Alexander Vance (Admin)', 'Samantha Carter', 'REF-GOV-SAT-99', generate_tx_hash(), 'ACTIVE'),
        ('NFT-2026-6C33D4', 'Biometric Vault Authorization Certificate', 'Certificate', 'Multi-sig biometric ledger access token for datacenter alpha.', 'Elena Rostova (User)', 'Dr. Sarah Connor (Manager)', 'REF-CERT-BIO-44', generate_tx_hash(), 'ACTIVE'),
        ('NFT-2026-2F55C1', 'Autonomous Drone Fleet Firmware v4', 'Digital Document', 'Encrypted build payload for autonomous perimeter security drones.', 'Elena Rostova (User)', 'Elena Rostova (User)', 'REF-FW-DRONE-88', generate_tx_hash(), 'ACTIVE'),
        ('NFT-2026-7A99B0', 'Global Financial Node Access Voucher', 'Other', 'Interbank transaction routing token with timestamp lock.', 'David Sterling', 'David Sterling', 'REF-FIN-VOUCH-12', generate_tx_hash(), 'ACTIVE')
    ]
    for asset in assets_data:
        cursor.execute('''
            INSERT INTO assets (nft_id, name, asset_type, description, current_owner, original_owner, value_ref, tx_hash, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', asset)

    # 4. Seed Ownership History
    history_data = [
        ('NFT-2026-8F92A1', 'Sovereign Digital Identity Contract', 'GovSec System', 'Alexander Vance (Admin)', generate_tx_hash()),
        ('NFT-2026-9C41B3', 'Quantum Key Infrastructure Specs', 'Alexander Vance (Admin)', 'Dr. Sarah Connor (Manager)', generate_tx_hash()),
        ('NFT-2026-1E77A8', 'National Cyber Defense License 2026', 'GovSec Cyber Defense', 'Dr. Sarah Connor (Manager)', generate_tx_hash()),
        ('NFT-2026-6C33D4', 'Biometric Vault Authorization Certificate', 'Dr. Sarah Connor (Manager)', 'Elena Rostova (User)', generate_tx_hash())
    ]
    for h in history_data:
        cursor.execute('''
            INSERT INTO ownership_history (asset_nft_id, asset_name, previous_owner, new_owner, tx_hash)
            VALUES (?, ?, ?, ?, ?)
        ''', h)

    # 5. Seed Access Requests
    requests_data = [
        (4, 'user', 'NFT-2026-8F92A1', 'Sovereign Digital Identity Contract', 'View', 'Required for security compliance review.', 'Pending', None),
        (4, 'user', 'NFT-2026-9C41B3', 'Quantum Key Infrastructure Specs', 'Edit', 'Updating hardware module compatibility specs.', 'Approved', 'admin'),
        (2, 'manager', 'NFT-2026-3D88E2', 'Satellite Communications Encryption Key', 'Transfer', 'Re-assigning key to regional defense node.', 'Pending', None),
        (3, 'auditor', 'NFT-2026-2F55C1', 'Autonomous Drone Fleet Firmware v4', 'View', 'Routine firmware vulnerability scan.', 'Approved', 'manager'),
        (4, 'user', 'NFT-2026-3D88E2', 'Satellite Communications Encryption Key', 'Transfer', 'Direct control request.', 'Rejected', 'admin')
    ]
    for req in requests_data:
        cursor.execute('''
            INSERT INTO access_requests (user_id, username, asset_nft_id, asset_name, permission_requested, reason, status, reviewed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', req)

    # 6. Seed Audit Events (25 Events creating a tamper-evident SHA-256 hash chain)
    genesis_prev = "GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000000000000000000000000000"
    prev_h = genesis_prev

    audit_events_raw = [
        ('SYSTEM_INIT', 'Admin', 'SYSTEM_INITIALIZATION', 'SecureChain Node Alpha', 'SUCCESS'),
        ('admin', 'Admin', 'IDENTITY_CREATED', 'did:securechain:8f92a7c31e4b89a0', 'SUCCESS'),
        ('manager', 'Manager', 'IDENTITY_CREATED', 'did:securechain:9c41b3a28e7d11f0', 'SUCCESS'),
        ('auditor', 'Auditor', 'IDENTITY_CREATED', 'did:securechain:4b12f901a88c33d1', 'SUCCESS'),
        ('user', 'User', 'IDENTITY_CREATED', 'did:securechain:1e77a8291b4029c4', 'SUCCESS'),
        ('admin', 'Admin', 'ASSET_MINTED', 'NFT-2026-8F92A1', 'SUCCESS'),
        ('admin', 'Admin', 'ASSET_MINTED', 'NFT-2026-9C41B3', 'SUCCESS'),
        ('manager', 'Manager', 'ASSET_MINTED', 'NFT-2026-1E77A8', 'SUCCESS'),
        ('auditor', 'Auditor', 'ASSET_MINTED', 'NFT-2026-4B12F9', 'SUCCESS'),
        ('admin', 'Admin', 'ASSET_MINTED', 'NFT-2026-3D88E2', 'SUCCESS'),
        ('manager', 'Manager', 'ASSET_MINTED', 'NFT-2026-6C33D4', 'SUCCESS'),
        ('user', 'User', 'ASSET_MINTED', 'NFT-2026-2F55C1', 'SUCCESS'),
        ('admin', 'Admin', 'ASSET_MINTED', 'NFT-2026-7A99B0', 'SUCCESS'),
        ('admin', 'Admin', 'ROLE_ASSIGNED', 'Role: Manager -> Dr. Sarah Connor', 'SUCCESS'),
        ('auditor', 'Auditor', 'AUDIT_VERIFIED', 'Audit Trail Block Range #1-14', 'SUCCESS'),
        ('user', 'User', 'ACCESS_REQUESTED', 'Asset: NFT-2026-8F92A1 (View)', 'SUCCESS'),
        ('user', 'User', 'ACCESS_REQUESTED', 'Asset: NFT-2026-9C41B3 (Edit)', 'SUCCESS'),
        ('admin', 'Admin', 'ACCESS_APPROVED', 'Request #2 by user', 'SUCCESS'),
        ('user', 'User', 'UNAUTHORIZED_ACCESS', 'Resource: /admin/users', 'DENIED'),
        ('user', 'User', 'UNAUTHORIZED_ACCESS', 'Resource: /admin/system-reset', 'DENIED'),
        ('manager', 'Manager', 'ACCESS_REQUESTED', 'Asset: NFT-2026-3D88E2 (Transfer)', 'SUCCESS'),
        ('user', 'User', 'ACCESS_REQUESTED', 'Asset: NFT-2026-3D88E2 (Transfer)', 'SUCCESS'),
        ('admin', 'Admin', 'ACCESS_REJECTED', 'Request #5 by user', 'DENIED'),
        ('user', 'User', 'UNAUTHORIZED_ACCESS', 'Resource: /admin/assign-role', 'DENIED'),
        ('admin', 'Admin', 'SECURITY_CHECK', 'Full RBAC & Hash Audit Verification', 'SUCCESS')
    ]

    import datetime
    base_time = datetime.datetime.utcnow() - datetime.timedelta(hours=12)

    for i, ev in enumerate(audit_events_raw):
        ev_user, ev_role, ev_action, ev_resource, ev_status = ev
        tx_h = generate_tx_hash()
        time_str = (base_time + datetime.timedelta(minutes=i*25)).strftime('%Y-%m-%d %H:%M:%S')
        curr_h = calculate_audit_hash(prev_h, time_str, ev_user, ev_role, ev_action, ev_resource, ev_status, tx_h)
        
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, user, role, action, resource, status, tx_hash, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (time_str, ev_user, ev_role, ev_action, ev_resource, ev_status, tx_h, prev_h, curr_h))
        prev_h = curr_h

    conn.commit()
