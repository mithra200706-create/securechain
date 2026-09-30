from functools import wraps
from flask import session, redirect, url_for, flash, request, render_template
from database import get_db_connection, log_audit_event

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*allowed_roles):
    """
    Decorator to enforce Role-Based Access Control (RBAC).
    If role unauthorized, logs UNAUTHORIZED_ACCESS in Audit Log and returns Access Denied error.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in first.', 'warning')
                return redirect(url_for('login'))

            user_role = session.get('role', 'User')
            user_name = session.get('username', 'Unknown')

            if user_role not in allowed_roles:
                # Log unauthorized access attempt in database audit log
                conn = get_db_connection()
                resource_path = request.path
                log_audit_event(
                    conn,
                    user=user_name,
                    role=user_role,
                    action='UNAUTHORIZED_ACCESS',
                    resource=f"Path: {resource_path} (Required: {', '.join(allowed_roles)})",
                    status='DENIED'
                )
                conn.close()

                # Render Access Denied page/modal response
                return render_template(
                    'access_denied.html',
                    allowed_roles=allowed_roles,
                    current_role=user_role,
                    attempted_path=resource_path
                ), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    if 'user_id' in session:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        return user
    return None
