import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

from database import init_db, get_db_connection, log_audit_event
from auth import login_required, role_required, get_current_user
from utils import generate_did, generate_nft_id, generate_tx_hash, verify_hash_chain

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize Database on Startup
with app.app_context():
    init_db()

@app.context_processor
def inject_user():
    """Inject current user and role into all template contexts."""
    return dict(
        current_user=session.get('username'),
        current_role=session.get('role'),
        current_full_name=session.get('full_name')
    )

# ---------------------------------------------------------
# AUTHENTICATION ROUTES
# ---------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        selected_role = request.form.get('role', '')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']

            # Log audit event for successful login
            log_audit_event(
                conn,
                user=user['username'],
                role=user['role'],
                action='LOGIN',
                resource='Authentication Portal',
                status='SUCCESS'
            )
            conn.close()

            flash(f'Welcome back, {user["full_name"]}! Authenticated as {user["role"]}.', 'success')
            return redirect(url_for('dashboard'))
        else:
            if conn:
                log_audit_event(
                    conn,
                    user=username if username else 'Unknown',
                    role=selected_role if selected_role else 'Visitor',
                    action='LOGIN',
                    resource='Authentication Portal',
                    status='DENIED'
                )
                conn.close()
            flash('Invalid username or password. Please check demo credentials.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        conn = get_db_connection()
        log_audit_event(
            conn,
            user=session['username'],
            role=session.get('role', 'User'),
            action='LOGOUT',
            resource='Session Ended',
            status='SUCCESS'
        )
        conn.close()
    session.clear()
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('login'))


# ---------------------------------------------------------
# DASHBOARD ROUTE
# ---------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()

    identities_count = conn.execute('SELECT COUNT(*) FROM identities').fetchone()[0]
    assets_count = conn.execute('SELECT COUNT(*) FROM assets').fetchone()[0]
    roles_count = conn.execute('SELECT COUNT(DISTINCT role) FROM users').fetchone()[0]
    audit_count = conn.execute('SELECT COUNT(*) FROM audit_logs').fetchone()[0]

    recent_activity = conn.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 6').fetchall()
    recent_assets = conn.execute('SELECT * FROM assets ORDER BY id DESC LIMIT 5').fetchall()
    recent_access = conn.execute('SELECT * FROM access_requests ORDER BY id DESC LIMIT 5').fetchall()

    # Category counts for Chart.js
    category_rows = conn.execute('''
        SELECT asset_type, COUNT(*) as count 
        FROM assets 
        GROUP BY asset_type
    ''').fetchall()
    categories = [r['asset_type'] for r in category_rows]
    category_counts = [r['count'] for r in category_rows]

    conn.close()

    return render_template(
        'dashboard.html',
        identities_count=identities_count,
        assets_count=assets_count,
        roles_count=roles_count,
        audit_count=audit_count,
        recent_activity=recent_activity,
        recent_assets=recent_assets,
        recent_access=recent_access,
        categories=categories,
        category_counts=category_counts
    )


# ---------------------------------------------------------
# DECENTRALIZED IDENTITY (DID) MODULE
# ---------------------------------------------------------

@app.route('/identities')
@login_required
def identities():
    conn = get_db_connection()
    identities_list = conn.execute('SELECT * FROM identities ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('identities.html', identities=identities_list)

@app.route('/identities/create', methods=['POST'])
@login_required
def create_identity():
    full_name = request.form.get('full_name', '').strip()
    email = request.form.get('email', '').strip()
    organization = request.form.get('organization', '').strip()
    role = request.form.get('role', 'User')

    if not full_name or not email or not organization:
        flash('All fields are required to generate a Decentralized Identity.', 'danger')
        return redirect(url_for('identities'))

    did_uri = generate_did(full_name, email)
    conn = get_db_connection()

    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO identities (did, full_name, email, organization, role, status)
            VALUES (?, ?, ?, ?, ?, 'VERIFIED')
        ''', (did_uri, full_name, email, organization, role))
        
        tx_hash, _ = log_audit_event(
            conn,
            user=session.get('username', 'System'),
            role=session.get('role', 'User'),
            action='IDENTITY_CREATED',
            resource=f"DID: {did_uri} ({full_name})",
            status='SUCCESS'
        )
        conn.commit()
        flash(f'Decentralized Identity Created Successfully! DID: {did_uri}', 'success')
    except Exception as e:
        flash(f'Error creating DID: {str(e)}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('identities'))


# ---------------------------------------------------------
# ASSET REGISTRY / NFT MODULE
# ---------------------------------------------------------

@app.route('/assets')
@login_required
def assets():
    conn = get_db_connection()
    assets_list = conn.execute('SELECT * FROM assets ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('assets.html', assets=assets_list)

@app.route('/assets/mint', methods=['POST'])
@login_required
def mint_asset():
    name = request.form.get('name', '').strip()
    asset_type = request.form.get('asset_type', 'Digital Document')
    description = request.form.get('description', '').strip()
    owner = request.form.get('owner', session.get('full_name', 'System Owner')).strip()
    value_ref = request.form.get('value_ref', 'REF-2026-NUL').strip()

    if not name:
        flash('Asset Name is required.', 'danger')
        return redirect(url_for('assets'))

    nft_id = generate_nft_id()
    tx_hash = generate_tx_hash()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO assets (nft_id, name, asset_type, description, current_owner, original_owner, value_ref, tx_hash, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
        ''', (nft_id, name, asset_type, description, owner, owner, value_ref, tx_hash))

        # Add initial ownership history entry
        cursor.execute('''
            INSERT INTO ownership_history (asset_nft_id, asset_name, previous_owner, new_owner, tx_hash)
            VALUES (?, ?, ?, ?, ?)
        ''', (nft_id, name, 'System Genesis', owner, tx_hash))

        log_audit_event(
            conn,
            user=session.get('username', 'System'),
            role=session.get('role', 'User'),
            action='ASSET_MINTED',
            resource=f"NFT Asset: {nft_id} ({name})",
            status='SUCCESS',
            tx_hash=tx_hash
        )
        conn.commit()
        flash(f'NFT Asset Minted Successfully! Asset ID: {nft_id}', 'success')
    except Exception as e:
        flash(f'Error minting asset: {str(e)}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('assets'))


# ---------------------------------------------------------
# ROLE-BASED ACCESS CONTROL (RBAC) & ACCESS REQUESTS
# ---------------------------------------------------------

@app.route('/access-control')
@login_required
def access_control():
    conn = get_db_connection()
    users_list = conn.execute('SELECT * FROM users ORDER BY id ASC').fetchall()
    conn.close()
    return render_template('access_control.html', users=users_list)

@app.route('/access-requests')
@login_required
def access_requests():
    conn = get_db_connection()
    assets_list = conn.execute('SELECT nft_id, name FROM assets WHERE status = "ACTIVE"').fetchall()
    requests_list = conn.execute('SELECT * FROM access_requests ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('access_requests.html', assets=assets_list, requests=requests_list)

@app.route('/access-requests/create', methods=['POST'])
@login_required
def create_access_request():
    asset_nft_id = request.form.get('asset_nft_id')
    permission = request.form.get('permission', 'View')
    reason = request.form.get('reason', '').strip()

    if not asset_nft_id or not reason:
        flash('Please select an asset and provide a valid reason.', 'danger')
        return redirect(url_for('access_requests'))

    conn = get_db_connection()
    asset = conn.execute('SELECT name FROM assets WHERE nft_id = ?', (asset_nft_id,)).fetchone()
    asset_name = asset['name'] if asset else 'Unknown Asset'

    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO access_requests (user_id, username, asset_nft_id, asset_name, permission_requested, reason, status)
        VALUES (?, ?, ?, ?, ?, ?, 'Pending')
    ''', (session['user_id'], session['username'], asset_nft_id, asset_name, permission, reason))

    log_audit_event(
        conn,
        user=session['username'],
        role=session.get('role', 'User'),
        action='ACCESS_REQUESTED',
        resource=f"Asset: {asset_nft_id} ({permission})",
        status='SUCCESS'
    )
    conn.commit()
    conn.close()

    flash(f'Access Request submitted for {asset_name}. Pending review by Admin/Manager.', 'success')
    return redirect(url_for('access_requests'))

@app.route('/access-requests/<int:req_id>/action', methods=['POST'])
@login_required
@role_required('Admin', 'Manager')
def handle_access_request(req_id):
    action_type = request.form.get('action_type') # 'Approve' or 'Reject'
    
    conn = get_db_connection()
    req = conn.execute('SELECT * FROM access_requests WHERE id = ?', (req_id,)).fetchone()

    if not req:
        flash('Request not found.', 'danger')
        conn.close()
        return redirect(url_for('access_requests'))

    new_status = 'Approved' if action_type == 'Approve' else 'Rejected'
    conn.execute('''
        UPDATE access_requests 
        SET status = ?, reviewed_by = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (new_status, session['username'], req_id))

    audit_action = 'ACCESS_APPROVED' if action_type == 'Approve' else 'ACCESS_REJECTED'
    log_audit_event(
        conn,
        user=session['username'],
        role=session['role'],
        action=audit_action,
        resource=f"Request #{req_id} ({req['asset_nft_id']} for {req['username']})",
        status='SUCCESS' if action_type == 'Approve' else 'DENIED'
    )
    conn.commit()
    conn.close()

    flash(f'Request #{req_id} has been {new_status}. Audit event recorded.', 'info')
    return redirect(url_for('access_requests'))


# ---------------------------------------------------------
# OWNERSHIP HISTORY MODULE
# ---------------------------------------------------------

@app.route('/ownership')
@login_required
def ownership():
    conn = get_db_connection()
    selected_nft_id = request.args.get('nft_id')
    assets_list = conn.execute('SELECT nft_id, name FROM assets').fetchall()

    if not selected_nft_id and assets_list:
        selected_nft_id = assets_list[0]['nft_id']

    selected_asset = None
    history_records = []
    if selected_nft_id:
        selected_asset = conn.execute('SELECT * FROM assets WHERE nft_id = ?', (selected_nft_id,)).fetchone()
        history_records = conn.execute('''
            SELECT * FROM ownership_history 
            WHERE asset_nft_id = ? 
            ORDER BY id ASC
        ''', (selected_nft_id,)).fetchall()

    conn.close()
    return render_template(
        'ownership.html',
        assets=assets_list,
        selected_asset=selected_asset,
        history=history_records,
        selected_nft_id=selected_nft_id
    )


# ---------------------------------------------------------
# AUDIT TRAIL MODULE (SHA-256 Hash Chain)
# ---------------------------------------------------------

@app.route('/audit')
@login_required
def audit():
    conn = get_db_connection()
    audit_records = conn.execute('SELECT * FROM audit_logs ORDER BY id ASC').fetchall()
    
    # Run hash chain verification
    verification = verify_hash_chain(audit_records)
    conn.close()

    return render_template('audit.html', audit_logs=audit_records, verification=verification)

@app.route('/audit/verify', methods=['GET', 'POST'])
@login_required
def verify_audit():
    conn = get_db_connection()
    audit_records = conn.execute('SELECT * FROM audit_logs ORDER BY id ASC').fetchall()
    verification = verify_hash_chain(audit_records)
    
    # Log the audit verification action itself
    log_audit_event(
        conn,
        user=session.get('username', 'System'),
        role=session.get('role', 'User'),
        action='AUDIT_VERIFIED',
        resource=f"Entire Log Chain ({len(audit_records)} Records)",
        status='SUCCESS' if verification['valid'] else 'WARNING'
    )
    conn.close()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(verification)

    flash(verification['message'], 'success' if verification['valid'] else 'danger')
    return redirect(url_for('audit'))


# ---------------------------------------------------------
# SECURITY CENTER
# ---------------------------------------------------------

@app.route('/security')
@login_required
def security():
    conn = get_db_connection()
    unauthorized_attempts = conn.execute('''
        SELECT COUNT(*) FROM audit_logs 
        WHERE action = "UNAUTHORIZED_ACCESS" OR status = "DENIED"
    ''').fetchone()[0]

    unauthorized_logs = conn.execute('''
        SELECT * FROM audit_logs 
        WHERE action = "UNAUTHORIZED_ACCESS" OR status = "DENIED"
        ORDER BY id DESC LIMIT 10
    ''').fetchall()

    recent_security_events = conn.execute('''
        SELECT * FROM audit_logs 
        ORDER BY id DESC LIMIT 8
    ''').fetchall()

    audit_records = conn.execute('SELECT * FROM audit_logs ORDER BY id ASC').fetchall()
    verification = verify_hash_chain(audit_records)

    conn.close()
    return render_template(
        'security.html',
        unauthorized_attempts=unauthorized_attempts,
        unauthorized_logs=unauthorized_logs,
        recent_security_events=recent_security_events,
        verification=verification
    )


# ---------------------------------------------------------
# ADMIN PANEL (ADMIN ONLY)
# ---------------------------------------------------------

@app.route('/admin')
@login_required
@role_required('Admin')
def admin_panel():
    conn = get_db_connection()
    users_list = conn.execute('SELECT * FROM users ORDER BY id ASC').fetchall()
    identities_list = conn.execute('SELECT * FROM identities ORDER BY id DESC').fetchall()
    assets_list = conn.execute('SELECT * FROM assets ORDER BY id DESC').fetchall()
    requests_list = conn.execute('SELECT * FROM access_requests ORDER BY id DESC').fetchall()
    audit_records = conn.execute('SELECT * FROM audit_logs ORDER BY id ASC').fetchall()
    verification = verify_hash_chain(audit_records)
    conn.close()

    return render_template(
        'admin.html',
        users=users_list,
        identities=identities_list,
        assets=assets_list,
        requests=requests_list,
        verification=verification
    )

@app.route('/admin/assign-role', methods=['POST'])
@login_required
@role_required('Admin')
def assign_role():
    target_user_id = request.form.get('user_id')
    new_role = request.form.get('new_role')

    conn = get_db_connection()
    user = conn.execute('SELECT username, role FROM users WHERE id = ?', (target_user_id,)).fetchone()

    if user:
        old_role = user['role']
        conn.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, target_user_id))
        
        log_audit_event(
            conn,
            user=session['username'],
            role=session['role'],
            action='ROLE_ASSIGNED',
            resource=f"User {user['username']}: {old_role} -> {new_role}",
            status='SUCCESS'
        )
        conn.commit()
        flash(f'Role updated successfully for {user["username"]} to {new_role}.', 'success')

    conn.close()
    return redirect(url_for('admin_panel'))

# Route specifically designed for demoing ACCESS DENIED when non-admin clicks it
@app.route('/admin/demo-restricted')
@login_required
@role_required('Admin')
def demo_restricted():
    flash('Admin Access Granted. Welcome to the restricted vault.', 'success')
    return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    print("=" * 60)
    print(" SecureChain - Blockchain Identity & Asset Platform Prototype ")
    print(" Server launching on http://127.0.0.1:5000 ")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=True)
