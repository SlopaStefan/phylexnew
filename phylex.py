#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PHYLEX TREE BROWSER - Production Version for Azure App Service
Optimized for deployment via GitHub Actions to Azure
HTTPS-ready with production security settings
"""

import argparse
import csv
import io
import secrets
import os
import re
import logging
from datetime import datetime
from flask import Flask, jsonify, request, Response, session
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import sql
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Use persistent secret key from environment or generate one
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Security: Session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Set True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600  # 1 hour timeout
)

# -- Database configuration --
# SECURITY: All credentials and connection details must be set via environment variables
# Required environment variables:
#   DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS, DB_USER_RO, DB_PASS_RO
PG_CONFIG_READONLY = {
    'host': os.environ.get('DB_HOST'),
    'port': int(os.environ.get('DB_PORT', '5432')),
    'database': os.environ.get('DB_NAME'),
    'user': os.environ.get('DB_USER_RO'),
    'password': os.environ.get('DB_PASS_RO'),
    'client_encoding': 'UTF8',
    'sslmode': 'require'
}

PG_CONFIG_WRITE = {
    'host': os.environ.get('DB_HOST'),
    'port': int(os.environ.get('DB_PORT', '5432')),
    'database': os.environ.get('DB_NAME'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASS'),
    'client_encoding': 'UTF8',
    'sslmode': 'require'
}

def get_client_ip():
    """Get the real client IP address, handling proxies"""
    # Check X-Forwarded-For header (from proxies/load balancers)
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, take the first one
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr or 'unknown'
    return ip

def audit_log(action, details=None, user=None, status='SUCCESS'):
    """
    Audit logging for security events

    Args:
        action: Description of the action (e.g., 'LOGIN', 'DELETE_NODE')
        details: Additional details about the action
        user: Username (if None, uses current session user)
        status: SUCCESS, FAILED, DENIED, etc.
    """
    if user is None:
        user = get_current_user() or 'anonymous'

    ip = get_client_ip()

    # Build log message
    log_parts = [
        f"[AUDIT]",
        f"User={user}",
        f"IP={ip}",
        f"Action={action}",
        f"Status={status}"
    ]

    if details:
        log_parts.append(f"Details={details}")

    log_message = " | ".join(log_parts)

    if status in ['FAILED', 'DENIED', 'ERROR']:
        logger.warning(log_message)
    else:
        logger.info(log_message)

# Plaintext password verification (passwords stored in clear text in database)
logger.info("Using plaintext password verification")

def verify_password(password, stored_password):
    """Verify password against plaintext stored password"""
    return password == stored_password

def load_users_from_db():
    """
    Load users from database
    Returns dict of {username: {'password_hash': str, 'role': str}}
    Falls back to empty dict if table doesn't exist
    """
    try:
        conn = get_db(readonly=True)
        cursor = conn.cursor()

        # Check if users table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'users'
            ) as exists
        """)

        result = cursor.fetchone()
        if not result['exists']:
            logger.warning("Users table not found - authentication disabled")
            logger.warning("Run: psql -U phylex -d phylex -f setup_users_table.sql")
            logger.warning("Then: python manage_users.py setup")
            cursor.close()
            conn.close()
            return {}

        # Load active users
        cursor.execute("""
            SELECT username, password, role
            FROM users
            WHERE is_active = TRUE
        """)

        users = {}
        for row in cursor.fetchall():
            users[row['username']] = {
                'password': row['password'],
                'role': row['role']
            }

        cursor.close()
        conn.close()

        logger.info(f"Loaded {len(users)} user(s) from database")
        return users

    except Exception as e:
        import traceback
        logger.error(f"Error loading users from database: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        logger.warning("Authentication disabled - no users loaded")
        return {}

def update_last_login(username):
    """Update last login timestamp for user"""
    try:
        conn = get_db()  # Use write connection
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET last_login = CURRENT_TIMESTAMP
            WHERE username = %s
        """, (username,))

        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not update last login for {username}: {e}")

# -- Users loaded from database --
USERS = {}  # Will be populated by load_users_from_db() at startup

# Security: Input validation
def validate_node_id(node_id):
    """Validate node ID format"""
    if not node_id or not isinstance(node_id, str):
        return False
    if len(node_id) > 100:
        return False
    # Allow alphanumeric and hyphens only
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', node_id))

def validate_node_name(name):
    """Validate node name"""
    if not name or not isinstance(name, str):
        return False
    if len(name) > 500:
        return False
    # Prevent null bytes and control characters
    if '\x00' in name or any(ord(c) < 32 and c not in '\n\r\t' for c in name):
        return False
    return True

def sanitize_error(error_msg):
    """Sanitize error messages to avoid information disclosure"""
    # Log full error server-side
    print(f"ERROR: {error_msg}", flush=True)
    # Return generic message to client
    if "does not exist" in str(error_msg).lower():
        return "Resource not found"
    if "duplicate" in str(error_msg).lower():
        return "Duplicate entry"
    if "permission" in str(error_msg).lower() or "denied" in str(error_msg).lower():
        return "Permission denied"
    return "An error occurred"

# -- In-memory state (loaded from PostgreSQL) --
state = {}
name_to_id = {}
parent_children = defaultdict(list)
homo_path_ids = set()

def get_db(readonly=False):
    """Get database connection based on user role"""
    config = PG_CONFIG_READONLY if readonly else PG_CONFIG_WRITE
    return psycopg2.connect(**config, cursor_factory=RealDictCursor)

def get_current_user():
    """Get current user info from session"""
    return session.get('user')

def get_user_role():
    """Get current user role"""
    user = get_current_user()
    if not user:
        return None
    return USERS.get(user, {}).get('role')

def load_db():
    """Load phylogenetic tree from PostgreSQL into memory"""
    global state, name_to_id, parent_children, homo_path_ids

    try:
        logger.info("="*60)
        logger.info("DATABASE CONNECTION")
        logger.info("="*60)
        logger.info(f"Host: {os.environ.get('DB_HOST', 'NOT SET')}")
        logger.info(f"Database: {os.environ.get('DB_NAME', 'NOT SET')}")
        logger.info(f"User: {os.environ.get('DB_USER_RO', 'NOT SET')}")
        logger.info(f"SSL Mode: require")
        logger.info("="*60)

        print("Connecting to PostgreSQL...", flush=True)
        conn = get_db(readonly=True)  # Use readonly for loading
        cursor = conn.cursor()

        print("Loading clades into RAM...", flush=True)
        cursor.execute("""
            SELECT node_id, node_name, parent_id, description, traits,
                   other_names, extant
            FROM clades
        """)

        rows = cursor.fetchall()
        state = {}
        name_to_id = {}
        parent_children = defaultdict(list)

        for row in rows:
            clade_id = row['node_id']
            state[clade_id] = {
                'name': row['node_name'],
                'parent': row['parent_id'],
                'description': row['description'],
                'traits': row['traits'],
                'otherNames': row['other_names'],
                'extant': row['extant']
            }

            # Build name index
            if row['node_name']:
                name_to_id[row['node_name'].lower()] = clade_id

            # Build parent-children map
            if row['parent_id']:
                parent_children[row['parent_id']].append(clade_id)

        cursor.close()
        conn.close()

        print(f"  {len(state):,} live clades", flush=True)
        logger.info(f"Loaded {len(state):,} clades successfully")

        # Build homo sapiens path
        _rebuild_homo_path()
        print(f"  Path to Homo sapiens: {len(homo_path_ids)} nodes", flush=True)
        logger.info(f"Homo sapiens path: {len(homo_path_ids)} nodes")

    except Exception as e:
        logger.error("="*60)
        logger.error("FATAL ERROR: Failed to load database!")
        logger.error("="*60)
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Error message: {str(e)}")
        logger.error(f"DB_HOST: {os.environ.get('DB_HOST', 'NOT SET')}")
        logger.error(f"DB_NAME: {os.environ.get('DB_NAME', 'NOT SET')}")
        logger.error(f"DB_USER_RO: {os.environ.get('DB_USER_RO', 'NOT SET')}")
        logger.error("="*60)
        import traceback
        logger.error(traceback.format_exc())
        raise  # Re-raise to prevent app from starting with no data

def require_auth(min_role='editor'):
    """Decorator to require authentication for endpoints"""
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            role = get_user_role()
            user = get_current_user()
            endpoint = request.endpoint or f.__name__

            if min_role == 'admin' and role != 'admin':
                if not role:
                    audit_log(f'ACCESS_DENIED', f'Endpoint={endpoint}, Required=admin, User=unauthenticated', 
                             user='anonymous', status='DENIED')
                    return jsonify({"error": "You must be admin"}), 403
                audit_log(f'ACCESS_DENIED', f'Endpoint={endpoint}, Required=admin, UserRole={role}', 
                         user=user, status='DENIED')
                return jsonify({"error": "You must login as Admin"}), 403

            if min_role == 'editor' and not role:
                audit_log(f'ACCESS_DENIED', f'Endpoint={endpoint}, Required=editor, User=unauthenticated', 
                         user='anonymous', status='DENIED')
                return jsonify({"error": "You must be admin"}), 403

            return f(*args, **kwargs)
        return wrapped
    return decorator

def _rebuild_homo_path():
    """Rebuild the path from root to Homo sapiens"""
    global homo_path_ids
    homo_path_ids = set()
    all_ids = set(state.keys())
    hs_id = name_to_id.get("homo sapiens")

    if hs_id:
        cur = hs_id
        while cur:
            homo_path_ids.add(cur)
            p = (state.get(cur) or {}).get("parent")
            cur = str(p) if p and str(p) in all_ids else None

def node_dict(cid):
    """Convert internal node data to API response format"""
    d = state.get(cid, {})
    pid = str(d.get("parent", "") or "")

    # Format traits for display
    traits = (d.get("traits") or "").strip()

    return {
        "id": cid,
        "name": (d.get("name") or "").strip(),
        "description": (d.get("description") or "").strip(),
        "traits": traits,
        "extant": d.get("extant"),
        "parent_id": pid,
        "parent_name": (state.get(pid, {}).get("name") or "").strip(),
        "child_count": len(parent_children.get(cid, [])),
        "on_path": cid in homo_path_ids,
    }

def _generate_node_id():
    """Generate a unique node ID"""
    while True:
        nid = secrets.token_hex(12)
        if nid not in state:
            return nid

# -- API Routes --

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phylogeny Explorer New & Revised</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:system-ui,-apple-system,sans-serif; background:#0a1929; color:#e6edf3; overflow:hidden; }
.header { background:#13294b; border-bottom:2px solid #1d3a5f; padding:14px 20px; display:flex; align-items:center; gap:20px; }
.header h1 { font-size:22px; color:#667eea; margin:0; }
.header-stats { margin-left:auto; display:flex; gap:16px; font-size:13px; color:#8b949e; }
.stat-item { display:flex; flex-direction:column; align-items:flex-end; }
.stat-value { font-size:20px; font-weight:600; color:#48bb78; }
.stat-label { font-size:11px; text-transform:uppercase; letter-spacing:0.5px; margin-top:2px; }
.search-wrap { position:relative; flex:1; max-width:600px; }
#searchInput { width:100%; padding:10px 14px; border:1px solid #2d4663; border-radius:6px; background:#0f2942; color:#e6edf3; font-size:14px; }
#searchInput:focus { outline:none; border-color:#667eea; }
.search-dropdown { position:absolute; top:100%; left:0; right:0; background:#13294b; border:1px solid #2d4663; border-radius:6px; margin-top:4px; max-height:400px; overflow-y:auto; box-shadow:0 8px 24px rgba(0,0,0,0.4); z-index:100; display:none; }
.search-dropdown.open { display:block; }
.sd-item { padding:12px 14px; cursor:pointer; border-bottom:1px solid #1d3a5f; }
.sd-item:hover { background:#1d3a5f; }
.sd-item.on-path { border-left:3px solid #667eea; }
.sd-meta { font-size:12px; color:#8b949e; margin-top:4px; }
.toolbar { background:#0f2942; border-bottom:1px solid #1d3a5f; padding:10px 20px; display:none; align-items:center; gap:10px; flex-wrap:wrap; }
.toolbar.authenticated { display:flex; }
.tb-input { padding:8px 10px; border:1px solid #2d4663; border-radius:4px; background:#13294b; color:#e6edf3; font-size:13px; width:180px; }
.tb-btn { padding:8px 14px; border:none; border-radius:4px; cursor:pointer; font-size:13px; font-weight:500; transition:all 0.2s; }
.btn-move { background:#667eea; color:white; }
.btn-move:hover { background:#5568d3; }
.btn-add { background:#48bb78; color:white; }
.btn-add:hover { background:#38a169; }
.btn-export { background:#4299e1; color:white; }
.btn-export:hover { background:#3182ce; }
.btn-restore { background:#ed8936; color:white; }
.btn-restore:hover { background:#dd6b20; }
.btn-backup { background:#9f7aea; color:white; }
.btn-backup:hover { background:#805ad5; }
.btn-edit { background:#4299e1; color:white; font-size:13px; }
.btn-edit:hover { background:#3182ce; }
.btn-delete { background:#f56565; color:white; font-size:13px; }
.btn-delete:hover { background:#e53e3e; }
.tb-sep { color:#4a5568; font-size:16px; }
.tb-status { margin-left:10px; font-size:13px; color:#8b949e; }
.tb-status.tb-ok { color:#48bb78; }
.tb-status.tb-err { color:#f56565; }
.tb-right { margin-left:auto; display:flex; gap:8px; }
.app { display:flex; height:calc(100vh - 112px); }
.sidebar { width:280px; background:#0f2942; border-right:1px solid #1d3a5f; overflow-y:auto; flex-shrink:0; }
.sidebar-title { padding:14px 16px; font-size:12px; font-weight:600; color:#8b949e; text-transform:uppercase; letter-spacing:1px; background:#13294b; border-bottom:1px solid #1d3a5f; }
.crumb { padding:10px 16px; cursor:pointer; border-left:3px solid transparent; transition:all 0.2s; }
.crumb:hover { background:#13294b; }
.crumb.active { background:#13294b; border-left-color:#667eea; color:#667eea; font-weight:500; }
.crumb.on-path { border-left-color:#48bb78; }
.main { flex:1; overflow-y:auto; padding:24px; }
.node-header { background:#13294b; border-radius:8px; padding:20px; margin-bottom:24px; border:1px solid #1d3a5f; }
.node-header.on-path { border-color:#48bb78; }
.node-title { font-size:28px; font-weight:600; color:#e6edf3; margin-bottom:8px; }
.node-title.on-path { color:#48bb78; }
.badges { display:flex; gap:8px; margin-bottom:8px; }
.badge { padding:4px 10px; border-radius:12px; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; }
.badge-path { background:#48bb7833; color:#48bb78; }
.badge-extant { background:#48bb7833; color:#48bb78; }
.badge-extinct { background:#f5656533; color:#f56565; }
.node-desc { font-size:14px; line-height:1.6; color:#c9d1d9; margin-top:12px; }
.children-title { font-size:16px; font-weight:600; color:#8b949e; margin-bottom:12px; }
.children-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(220px, 1fr)); gap:12px; }
.child-card { background:#13294b; border:1px solid #1d3a5f; border-radius:6px; padding:14px; cursor:pointer; transition:all 0.2s; }
.child-card:hover { background:#1d3a5f; transform:translateY(-2px); box-shadow:0 4px 12px rgba(0,0,0,0.3); }
.child-card.on-path { border-color:#48bb78; }
.child-name { font-size:14px; font-weight:500; color:#e6edf3; margin-bottom:6px; }
.child-meta { font-size:12px; color:#8b949e; }
.leaf-msg { padding:40px; text-align:center; color:#8b949e; font-size:14px; }
.error-msg { padding:40px; text-align:center; color:#f56565; font-size:14px; }
.node-id { font-family:monospace; font-size:12px; color:#667eea; margin:3px 0 10px; }
.node-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; align-items:center; }
.node-actions .btn-delete { margin-left:auto; }
#restoreFileInput { display:none; }
.btn-admin { background:#9f7aea; color:white; }
.btn-admin:hover { background:#805ad5; }
.btn-logout { background:#ed8936; color:white; }
.btn-logout:hover { background:#dd6b20; }
.login-modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.7); z-index:1000; align-items:center; justify-content:center; }
.login-modal.open { display:flex; }
.login-box { background:#13294b; border-radius:8px; padding:30px; width:400px; border:1px solid #2d4663; }
.login-title { font-size:20px; font-weight:600; color:#e6edf3; margin-bottom:20px; text-align:center; }
.login-input { width:100%; padding:10px; margin-bottom:15px; border:1px solid #2d4663; border-radius:4px; background:#0f2942; color:#e6edf3; font-size:14px; }
.login-input:focus { outline:none; border-color:#667eea; }
.login-btn { width:100%; padding:10px; border:none; border-radius:4px; background:#667eea; color:white; font-size:14px; font-weight:600; cursor:pointer; margin-top:10px; }
.login-btn:hover { background:#5568d3; }
.login-cancel { width:100%; padding:10px; border:none; border-radius:4px; background:#4a5568; color:white; font-size:14px; font-weight:600; cursor:pointer; margin-top:5px; }
.login-cancel:hover { background:#2d3748; }
.login-error { color:#f56565; font-size:13px; margin-top:10px; text-align:center; }
.user-info { display:flex; align-items:center; gap:8px; font-size:13px; color:#48bb78; }
#restoreFileInput { display:none; }
</style>
</head>
<body>
<div class="header">
  <h1>&#127807; Phylex [PostgreSQL]</h1>
  <div class="search-wrap">
      <input type="text" id="searchInput" placeholder="Search species or taxon...">
      <div class="search-dropdown" id="searchDropdown"></div>
    </div>
    <button class="tb-btn btn-export" onclick="exportCSV()" style="background:#4299e1;color:white;margin-left:auto;">&#8595;&nbsp;Export CSV</button>
    <div class="header-stats" style="margin-left:10px;">
      <div class="stat-item">
        <div class="stat-value" id="statTotal">-</div>
        <div class="stat-label">Total Nodes</div>
      </div>
      <div class="stat-item" style="cursor:pointer;" onclick="navigateToHomoSapiens()" title="Click to view Homo sapiens">
        <div class="stat-value" id="statPath">-</div>
        <div class="stat-label">Path to <span style="text-decoration:underline;">Homo sapiens</span></div>
      </div>
      <div id="authSection">
        <button class="tb-btn btn-admin" id="btnAdmin" onclick="showLogin()">Edit Mode</button>
      <div class="user-info" id="userInfo" style="display:none;">
        <span id="username"></span>
        <button class="tb-btn btn-logout" onclick="logout()">Logout</button>
      </div>
    </div>
  </div>
</div>
<div class="toolbar">
  <input class="tb-input" id="moveFrom" placeholder="Node ID to move" spellcheck="false">
  <span class="tb-sep">&#8594;</span>
  <input class="tb-input" id="moveTo" placeholder="New parent ID" spellcheck="false">
  <button class="tb-btn btn-move" onclick="moveNode()">Move</button>
  <input class="tb-input" id="childParent" placeholder="Parent ID for new child" spellcheck="false">
  <input class="tb-input" id="childName" placeholder="New child name" spellcheck="false">
  <button class="tb-btn btn-add" onclick="addChild()">Add Child</button>
  <span id="tbStatus" class="tb-status"></span>
  <div class="tb-right">
    <button class="tb-btn btn-export" onclick="exportCSV()">&#8595;&nbsp;Export CSV</button>
    <button class="tb-btn btn-restore" onclick="triggerRestore()">&#8593;&nbsp;Restore from CSV</button>
    <button class="tb-btn btn-backup" onclick="backupDB()">&#128190;&nbsp;Backup DB</button>
  </div>
</div>

<input type="file" id="restoreFileInput" accept=".csv" onchange="handleRestoreFile(event)">

<div class="login-modal" id="loginModal">
  <div class="login-box">
    <div class="login-title">Admin Login</div>
    <input type="text" id="loginUsername" class="login-input" placeholder="Username" autocomplete="username">
    <input type="password" id="loginPassword" class="login-input" placeholder="Password" autocomplete="current-password">
    <button class="login-btn" onclick="doLogin()">Login</button>
    <button class="login-cancel" onclick="closeLogin()">Cancel</button>
    <div class="login-error" id="loginError"></div>
  </div>
</div>

<div class="app">
  <div class="sidebar" id="sidebar">
    <div class="sidebar-title">Path</div>
  </div>
  <div class="main" id="main"></div>
</div>

<script>
let currentId = null;
let currentNode = null;
let searchTimer = null;
let isAuthenticated = false;

// ?? Boot ?????????????????????????????????????????????????????????????????????

async function boot() {
  showMainLoading();
  try {
    // Check session and load stats and root in parallel
    const [session, stats, root] = await Promise.all([
      get('/api/session'),
      get('/api/stats'),
      get('/api/root')
    ]);
    updateAuthUI(session);
    updateStats(stats);
    await navigate(root.id);
  } catch(e) {
    showError('Could not load root node: ' + e.message);
  }
}

function updateStats(stats) {
  document.getElementById('statTotal').textContent = stats.total_nodes.toLocaleString();
  document.getElementById('statPath').textContent = stats.homo_path_nodes.toLocaleString();
}

// ?? Navigation ???????????????????????????????????????????????????????????????

async function navigate(nodeId) {
  currentId = nodeId;
  showMainLoading();

  try {
    const [node, children, crumbs] = await Promise.all([
      get('/api/node/' + nodeId),
      get('/api/children/' + nodeId),
      get('/api/breadcrumb/' + nodeId),
    ]);
    renderSidebar(crumbs);
    renderMain(node, children);
  } catch(e) {
    showError('Navigation error: ' + e.message);
  }
}

// ?? Render ???????????????????????????????????????????????????????????????????

function renderSidebar(crumbs) {
  const el = document.getElementById('sidebar');
  let html = '<div class="sidebar-title">Path</div>';
  // Reverse the crumbs so Life is at bottom and current node at top
  const reversedCrumbs = [...crumbs].reverse();
  reversedCrumbs.forEach((c, i) => {
    const active  = i === 0 ? 'active' : '';
    const onPath  = c.on_path ? 'on-path' : '';
    html += `<div class="crumb ${active} ${onPath}" onclick="navigate('${c.id}')">${esc(c.name)}</div>`;
  });
  el.innerHTML = html;
}

function renderMain(node, children) {
  currentNode = node;
  const el = document.getElementById('main');

  const onPath   = node.on_path;
  const titleCls = onPath ? 'node-title on-path' : 'node-title';
  const hdrCls   = onPath ? 'node-header on-path' : 'node-header';

  let badges = '';
  if (onPath)                badges += '<span class="badge badge-path">&#10003;&nbsp;Path to Homo sapiens</span>';
  if (node.extant === true)  badges += '<span class="badge badge-extant">Living</span>';
  if (node.extant === false) badges += '<span class="badge badge-extinct">Extinct</span>';

  const desc = node.description
    ? `<div class="node-desc">${esc(node.description)}</div>` 
    : '<div class="node-desc" style="color:#666">No description</div>';

  const traits = node.traits 
    ? `<div style="margin-top:16px">
         <div style="color:#667eea;font-size:12px;font-weight:600;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">
           &#128220; Node Traits
         </div>
         <div class="node-desc" style="background:#0f3460;padding:12px;border-radius:6px;border-left:3px solid #667eea">
           ${esc(node.traits).replace(/\\n\\n/g, '<br><br>')}
         </div>
       </div>` 
    : '';

  let html = `
    <div class="${hdrCls}">
      <div class="${titleCls}">${esc(node.name)}</div>
      ${badges ? `<div class="badges">${badges}</div>` : ''}
      <div class="node-id">${esc(node.id)}</div>
      ${desc}
      ${traits}
      <div class="node-actions">
        ${isAuthenticated ? `
          <button class="tb-btn btn-edit" onclick="renameNode()">Rename Node</button>
          <button class="tb-btn btn-edit" onclick="editDescription()">Edit Description</button>
          <button class="tb-btn btn-delete" onclick="deleteCurrentNode()">Delete Node</button>
        ` : ''}
      </div>
    </div>
  `;

  if (children.length > 0) {
    html += `<div class="children-title">${children.length} children</div>
             <div class="children-grid">`;
    children.forEach(c => {
      const cls  = c.on_path ? 'child-card on-path' : 'child-card';
      const ext  = c.extant === false ? ' <span style="color:#e57373;font-size:11px">&#8224;</span>' : '';
      html += `
        <div class="${cls}" onclick="navigate('${c.id}')">
          <div class="child-name">${esc(c.name)}${ext}</div>
          <div class="child-meta">${c.child_count} children</div>
        </div>`;
    });
    html += '</div>';
  } else {
    html += '<div class="leaf-msg">Leaf node &mdash; no children</div>';
  }

  el.innerHTML = html;
}

// ?? Search ???????????????????????????????????????????????????????????????????

document.getElementById('searchInput').addEventListener('input', e => {
  clearTimeout(searchTimer);
  const q = e.target.value.trim();
  if (q.length < 2) { closeSearch(); return; }
  searchTimer = setTimeout(() => doSearch(q), 250);
});

document.addEventListener('click', e => {
  if (!e.target.closest('.search-wrap')) closeSearch();
});

async function doSearch(q) {
  try {
    const results = await get('/api/search?q=' + encodeURIComponent(q));
    const dd = document.getElementById('searchDropdown');
    if (!results.length) {
      dd.innerHTML = '<div class="sd-item" style="color:#666">No results</div>';
    } else {
      dd.innerHTML = results.map(r => `
        <div class="sd-item ${r.on_path ? 'on-path' : ''}" onclick="selectResult('${r.id}')">
          ${esc(r.name)}
          <div class="sd-meta">${r.child_count} children</div>
        </div>`).join('');
    }
    dd.classList.add('open');
  } catch(e) {}
}

function selectResult(id) {
  document.getElementById('searchInput').value = '';
  closeSearch();
  navigate(id);
}

function closeSearch() {
  document.getElementById('searchDropdown').classList.remove('open');
}

// ?? Utilities ????????????????????????????????????????????????????????????????

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
  return r.json();
}

function showMainLoading() {
  document.getElementById('main').innerHTML =
    '<div style="color:#555;padding:40px;text-align:center;font-size:14px">Loading...</div>';
}

function showError(msg) {
  document.getElementById('main').innerHTML =
    `<div class="error-msg">Error: ${esc(msg)}</div>`;
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function moveNode() {
  const fromId = document.getElementById('moveFrom').value.trim();
  const toId   = document.getElementById('moveTo').value.trim();
  if (!fromId || !toId) { tbStatus('Enter both node IDs', false); return; }
  try {
    const r = await fetch('/api/move', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({node_id: fromId, new_parent_id: toId})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || r.statusText);
    tbStatus('Moved "' + d.node_name + '" -> "' + d.new_parent_name + '"', true);
    document.getElementById('moveFrom').value = '';
    document.getElementById('moveTo').value   = '';
    if (currentId === fromId || currentId === d.old_parent_id || currentId === toId)
      navigate(currentId);
  } catch(e) { tbStatus('Error: ' + e.message, false); }
}

async function addChild() {
  const parentId = document.getElementById('childParent').value.trim();
  const name     = document.getElementById('childName').value.trim();
  if (!parentId || !name) { tbStatus('Enter parent ID and child name', false); return; }
  try {
    const r = await fetch('/api/add-child', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({parent_id: parentId, name})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || r.statusText);
    tbStatus('Added child "' + d.name + '" (' + d.id + ')', true);
    document.getElementById('childParent').value = '';
    document.getElementById('childName').value   = '';
    if (currentId === parentId) navigate(currentId);
  } catch(e) { tbStatus('Error: ' + e.message, false); }
}

async function renameNode() {
  if (!currentNode) return;
  const newName = prompt('Rename node:', currentNode.name);
  if (newName === null || newName.trim() === '') return;
  if (newName.trim() === currentNode.name) return;
  try {
    const r = await fetch('/api/rename/' + currentNode.id, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name: newName.trim()})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || r.statusText);
    tbStatus('Renamed from "' + d.old_name + '" to "' + d.new_name + '"', true);
    navigate(currentNode.id);
  } catch(e) { tbStatus('Error: ' + e.message, false); }
}

async function editDescription() {
  if (!currentNode) return;
  const description = prompt('Edit description for ' + currentNode.name, currentNode.description || '');
  if (description === null) return;
  try {
    const r = await fetch('/api/edit/' + currentNode.id, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({description})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || r.statusText);
    tbStatus('Description updated', true);
    navigate(currentNode.id);
  } catch(e) { tbStatus('Error: ' + e.message, false); }
}

async function deleteCurrentNode() {
  if (!currentNode) return;
  if (!confirm('Delete node "' + currentNode.name + '"? Only leaf nodes can be deleted.')) return;
  try {
    const r = await fetch('/api/delete/' + currentNode.id, {method:'POST'});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || r.statusText);
    tbStatus('Deleted "' + d.deleted_name + '"', true);
    navigate(d.parent_id || (await get('/api/root')).id);
  } catch(e) { tbStatus('Error: ' + e.message, false); }
}

function tbStatus(msg, ok) {
  const el = document.getElementById('tbStatus');
  el.textContent = msg;
  el.className   = 'tb-status ' + (ok ? 'tb-ok' : 'tb-err');
  clearTimeout(tbStatus._t);
  tbStatus._t = setTimeout(() => { el.className = 'tb-status'; }, 5000);
}

function exportCSV() { 
  window.location = '/api/export'; 
}

function backupDB() {
  if (!confirm('Backup all clades to timestamped backup table in PostgreSQL?')) return;
  fetch('/api/backup', {method:'POST'})
    .then(r => r.json())
    .then(d => tbStatus(d.message || 'Backup done', !d.error))
    .catch(e => tbStatus('Backup error: ' + e.message, false));
}

function triggerRestore() {
  if (!confirm('Restore database from CSV?\\n\\nThis will:\\n1. Create a backup of current database\\n2. Replace all data with CSV content\\n\\nContinue?')) return;
  document.getElementById('restoreFileInput').click();
}

async function handleRestoreFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  tbStatus('Restoring from CSV...', true);

  const formData = new FormData();
  formData.append('file', file);

  try {
    const r = await fetch('/api/restore', {
      method: 'POST',
      body: formData
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || r.statusText);

    tbStatus(d.message + ' (Backup: ' + d.backup + ')', true);

    // Reset file input
    event.target.value = '';

    // Reload the page after 2 seconds
    setTimeout(() => {
      window.location.reload();
    }, 2000);

  } catch(e) {
    tbStatus('Restore error: ' + e.message, false);
    event.target.value = '';
  }
}

// ?? Authentication ????????????????????????????????????????????????????

function updateAuthUI(session) {
  const btnAdmin = document.getElementById('btnAdmin');
  const userInfo = document.getElementById('userInfo');
  const username = document.getElementById('username');
  const toolbar = document.querySelector('.toolbar');

  isAuthenticated = session.authenticated;

  if (session.authenticated) {
    btnAdmin.style.display = 'none';
    userInfo.style.display = 'flex';
    const roleLabel = session.role === 'admin' ? ' (Admin)' : ' (Editor)';
    username.textContent = session.username + roleLabel;
    if (toolbar) toolbar.classList.add('authenticated');
  } else {
    btnAdmin.style.display = 'block';
    userInfo.style.display = 'none';
    if (toolbar) toolbar.classList.remove('authenticated');
  }
}

function showLogin() {
  document.getElementById('loginModal').classList.add('open');
  document.getElementById('loginUsername').value = '';
  document.getElementById('loginPassword').value = '';
  document.getElementById('loginError').textContent = '';
  document.getElementById('loginUsername').focus();
}

function closeLogin() {
  document.getElementById('loginModal').classList.remove('open');
}

async function doLogin() {
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  const errorEl = document.getElementById('loginError');

  if (!username || !password) {
    errorEl.textContent = 'Please enter username and password';
    return;
  }

  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, password})
    });
    const d = await r.json();

    if (!r.ok) {
      errorEl.textContent = d.error || 'Login failed';
      return;
    }

    closeLogin();
    updateAuthUI({authenticated: true, username: d.username, role: d.role});
    tbStatus('Logged in as ' + d.username, true);
  } catch(e) {
    errorEl.textContent = 'Login error: ' + e.message;
  }
}

async function logout() {
  if (!confirm('Logout?')) return;

  try {
    await fetch('/api/logout', {method: 'POST'});
    updateAuthUI({authenticated: false});
    tbStatus('Logged out', true);
    // Reload page to reset view to read-only mode
    setTimeout(() => window.location.reload(), 500);
  } catch(e) {
    tbStatus('Logout error: ' + e.message, false);
  }
}

// ?? Navigate to Homo sapiens ????????????????????????????????????????????????????????????

async function navigateToHomoSapiens() {
  try {
    // Search for Homo sapiens
    const results = await get('/api/search?q=homo%20sapiens');
    if (results && results.length > 0) {
      // Find exact match
      const exact = results.find(r => r.name.toLowerCase() === 'homo sapiens');
      if (exact) {
        await navigate(exact.id);
      } else {
        // Use first result
        await navigate(results[0].id);
      }
    } else {
      showError('Could not find Homo sapiens');
    }
  } catch(e) {
    showError('Error navigating to Homo sapiens: ' + e.message);
  }
}

// Allow Enter key to submit login
document.addEventListener('DOMContentLoaded', () => {
  const loginPassword = document.getElementById('loginPassword');
  if (loginPassword) {
    loginPassword.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') doLogin();
    });
  }
});

// Boot
boot();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return Response(HTML_TEMPLATE, mimetype="text/html")

@app.route("/favicon.ico")
def favicon():
    """Return empty favicon to prevent 404 errors"""
    # Minimal valid ICO file
    ico_data = b'\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00\x30\x00\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    return Response(ico_data, mimetype='image/x-icon')

@app.route("/api/login", methods=["POST"])
def api_login():
    """Login endpoint"""
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        audit_log('LOGIN_ATTEMPT', f'Missing credentials', user=username or 'unknown', status='FAILED')
        return jsonify({"error": "Username and password required"}), 400

    # Security: Rate limiting would go here in production

    user_info = USERS.get(username)

    if not user_info or not verify_password(password, user_info['password']):
        # Plaintext password comparison
        audit_log('LOGIN_ATTEMPT', f'Invalid credentials for user={username}', user=username, status='FAILED')
        return jsonify({"error": "Invalid credentials"}), 401

    session['user'] = username
    session.permanent = True  # Enable session timeout

    # Update last login timestamp
    update_last_login(username)

    audit_log('LOGIN', f'Role={user_info["role"]}', user=username, status='SUCCESS')

    return jsonify({
        "success": True,
        "username": username,
        "role": user_info['role']
    })

@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Logout endpoint"""
    user = get_current_user()
    session.pop('user', None)

    audit_log('LOGOUT', None, user=user, status='SUCCESS')

    return jsonify({"success": True})

@app.route("/api/session")
def api_session():
    """Get current session info"""
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False, "role": None})

    return jsonify({
        "authenticated": True,
        "username": user,
        "role": get_user_role()
    })

@app.route("/api/stats")
def api_stats():
    """Return database statistics"""
    return jsonify({
        "total_nodes": len(state),
        "homo_path_nodes": len(homo_path_ids)
    })

@app.route("/api/root")
def api_root():
    """Return the root node"""
    all_ids = set(state.keys())
    life_id = name_to_id.get("life")

    if not life_id:
        for cid, d in state.items():
            p = d.get("parent")
            if not p or str(p) not in all_ids:
                life_id = cid
                break

    if not life_id:
        return jsonify({"error": "root not found"}), 404

    return jsonify(node_dict(life_id))

@app.route("/api/node/<node_id>")
def api_node(node_id):
    if node_id not in state:
        return jsonify({"error": "not found"}), 404
    return jsonify(node_dict(node_id))

@app.route("/api/children/<node_id>")
def api_children(node_id):
    kids = []
    for cid in parent_children.get(node_id, []):
        d = state.get(cid, {})
        kids.append({
            "id": cid,
            "name": (d.get("name") or "").strip(),
            "extant": d.get("extant"),
            "child_count": len(parent_children.get(cid, [])),
            "on_path": cid in homo_path_ids,
        })
    kids.sort(key=lambda x: x["name"].lower())
    return jsonify(kids)

@app.route("/api/breadcrumb/<node_id>")
def api_breadcrumb(node_id):
    crumbs, cur, seen = [], node_id, set()
    all_ids = set(state.keys())

    while cur and cur not in seen:
        d = state.get(cur)
        if not d:
            break
        seen.add(cur)
        crumbs.append({
            "id": cur,
            "name": (d.get("name") or "").strip(),
            "on_path": cur in homo_path_ids
        })
        p = d.get("parent")
        cur = str(p) if p and str(p) in all_ids else None

    crumbs.reverse()
    return jsonify(crumbs)

@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").strip().lower()
    if len(q) < 2:
        return jsonify([])

    results = []
    for cid, d in state.items():
        n = (d.get("name") or "").lower()
        if q in n:
            results.append({
                "id": cid,
                "name": (d.get("name") or "").strip(),
                "child_count": len(parent_children.get(cid, [])),
                "on_path": cid in homo_path_ids,
            })
            if len(results) >= 50:
                break

    results.sort(key=lambda x: (x["name"].lower().index(q), x["name"].lower()))
    return jsonify(results)

@app.route("/api/export")
def api_export():
    all_ids = set(state.keys())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["node_id", "node_name", "parent_id", "parent_name", "description", "traits"])

    for cid, d in state.items():
        pid = str(d.get("parent", "") or "")
        pname = (state.get(pid, {}).get("name") or "").strip() if pid in all_ids else ""
        w.writerow([
            cid,
            (d.get("name") or "").strip(),
            pid,
            pname,
            (d.get("description") or "").strip(),
            (d.get("traits") or "").strip()
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=phylex_export.csv"}
    )

@app.route("/api/move", methods=["POST"])
@require_auth('editor')
def api_move():
    """Move a node to a new parent"""
    data = request.get_json() or {}
    node_id = (data.get("node_id") or "").strip()
    new_parent_id = (data.get("new_parent_id") or "").strip()

    if not node_id or not new_parent_id:
        return jsonify({"error": "node_id and new_parent_id are required"}), 400

    # Security: Validate input format
    if not validate_node_id(node_id):
        return jsonify({"error": "Invalid node_id format"}), 400
    if not validate_node_id(new_parent_id):
        return jsonify({"error": "Invalid parent_id format"}), 400

    if node_id not in state:
        return jsonify({"error": "Node not found"}), 404
    if new_parent_id not in state:
        return jsonify({"error": "Parent not found"}), 404
    if node_id == new_parent_id:
        return jsonify({"error": "Cannot move a node to itself"}), 400

    d = state[node_id]
    old_parent = str(d.get("parent", "") or "")
    node_name = (d.get("name") or "").strip()
    new_parent_name = (state[new_parent_id].get("name") or "").strip()

    try:
        # Update in PostgreSQL
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE clades SET parent_id = %s WHERE node_id = %s", (new_parent_id, node_id))
        conn.commit()
        cursor.close()
        conn.close()

        audit_log('MOVE_NODE', f'Node={node_name}[{node_id[:8]}...] -> NewParent={new_parent_name}[{new_parent_id[:8]}...]', status='SUCCESS')
    except Exception as e:
        audit_log('MOVE_NODE', f'Node={node_name}[{node_id[:8]}...] ERROR={str(e)}', status='ERROR')
        error_msg = str(e)
        return jsonify({"error": f"{sanitize_error(error_msg)}\n\nDetails: {error_msg}"}), 500

    # Update in-memory state
    if old_parent in parent_children:
        try:
            parent_children[old_parent].remove(node_id)
        except ValueError:
            pass

    state[node_id]["parent"] = new_parent_id
    parent_children[new_parent_id].append(node_id)
    _rebuild_homo_path()

    return jsonify({
        "node_id": node_id,
        "node_name": node_name,
        "old_parent_id": old_parent,
        "new_parent_id": new_parent_id,
        "new_parent_name": new_parent_name,
    })

@app.route("/api/add-child", methods=["POST"])
@require_auth('editor')
def api_add_child():
    """Add a new child node"""
    data = request.get_json() or {}
    parent_id = (data.get("parent_id") or "").strip()
    child_name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()

    if not parent_id or not child_name:
        return jsonify({"error": "parent_id and name are required"}), 400

    # Security: Validate inputs
    if not validate_node_id(parent_id):
        return jsonify({"error": "Invalid parent_id format"}), 400
    if not validate_node_name(child_name):
        return jsonify({"error": "Invalid name format"}), 400
    if len(description) > 5000:
        return jsonify({"error": "Description too long (max 5000 characters)"}), 400

    if parent_id not in state:
        return jsonify({"error": "Parent not found"}), 404

    new_id = _generate_node_id()
    new_data = {
        "name": child_name,
        "parent": parent_id,
        "otherNames": None,
        "extant": None,
        "description": description,
        "traits": None,
    }

    try:
        # Insert into PostgreSQL
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO clades (node_id, node_name, parent_id, description, traits, other_names, extant)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (new_id, child_name, parent_id, description, None, None, None))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Update in-memory state
    state[new_id] = new_data
    name_to_id[child_name.lower()] = new_id
    parent_children[parent_id].append(new_id)
    _rebuild_homo_path()

    parent_name = state.get(parent_id, {}).get('name', 'Unknown')
    audit_log('ADD_CHILD', f'Name={child_name}, Parent={parent_name}[{parent_id[:8]}...], NewID={new_id[:8]}...', status='SUCCESS')

    return jsonify(node_dict(new_id))

@app.route("/api/edit/<node_id>", methods=["POST"])
@require_auth('editor')
def api_edit(node_id):
    """Edit node description"""
    if node_id not in state:
        return jsonify({"error": "not found"}), 404

    data = request.get_json() or {}
    description = (data.get("description") or "").strip()

    try:
        # Update in PostgreSQL
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE clades SET description = %s WHERE node_id = %s", (description, node_id))
        conn.commit()
        cursor.close()
        conn.close()

        node_name = state.get(node_id, {}).get('name', 'Unknown')
        audit_log('EDIT_DESCRIPTION', f'Node={node_name}[{node_id[:8]}...], Length={len(description)} chars', status='SUCCESS')
    except Exception as e:
        audit_log('EDIT_DESCRIPTION', f'Node={node_id[:8]}... ERROR={str(e)}', status='ERROR')
        return jsonify({"error": str(e)}), 500

    # Update in-memory state
    state[node_id]["description"] = description

    return jsonify(node_dict(node_id))

@app.route("/api/rename/<node_id>", methods=["POST"])
@require_auth('editor')
def api_rename(node_id):
    """Rename a node"""
    if node_id not in state:
        return jsonify({"error": "not found"}), 404

    data = request.get_json() or {}
    new_name = (data.get("name") or "").strip()

    if not new_name:
        return jsonify({"error": "name is required"}), 400

    old_name = (state[node_id].get("name") or "").strip()

    try:
        # Update in PostgreSQL
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE clades SET node_name = %s WHERE node_id = %s", (new_name, node_id))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Update in-memory state
    state[node_id]["name"] = new_name

    # Update name index
    if old_name:
        name_to_id.pop(old_name.lower(), None)
    name_to_id[new_name.lower()] = node_id

    audit_log('RENAME_NODE', f'ID={node_id[:8]}..., OldName={old_name}, NewName={new_name}', status='SUCCESS')

    return jsonify({
        "id": node_id,
        "old_name": old_name,
        "new_name": new_name
    })

@app.route("/api/backup", methods=["POST"])
@require_auth('editor')
def api_backup():
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Security: Create backup with safe SQL identifier
        backup_suffix = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"clades_backup_{backup_suffix}"

        # Drop if exists (safe because we control the name)
        cursor.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(backup_name)))

        # Create backup table using safe identifier
        cursor.execute(sql.SQL("""
            CREATE TABLE {} AS 
            SELECT * FROM clades
        """).format(sql.Identifier(backup_name)))

        count = len(state)

        conn.commit()
        cursor.close()
        conn.close()

        audit_log('BACKUP_DATABASE', f'Table={backup_name}, Rows={count:,}', status='SUCCESS')

        return jsonify({"message": f"Backed up {count:,} clades to {backup_name} table"})
    except Exception as e:
        audit_log('BACKUP_DATABASE', f'ERROR={str(e)}', status='ERROR')
        error_msg = str(e)
        return jsonify({"error": f"{sanitize_error(error_msg)}\n\nDetails: {error_msg}"}), 500

@app.route("/api/restore", methods=["POST"])
@require_auth('admin')
def api_restore():
    """Restore database from uploaded CSV file"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        if not file.filename.endswith('.csv'):
            return jsonify({"error": "File must be a CSV"}), 400

        # Security: File size limit (10MB)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        if file_size > 10 * 1024 * 1024:
            return jsonify({"error": "File too large (max 10MB)"}), 400
        file.seek(0)

        # Read CSV content
        content = file.read().decode('utf-8')

        # Security: Limit number of rows
        line_count = content.count('\n')
        if line_count > 100000:
            return jsonify({"error": "Too many rows (max 100,000)"}), 400

        csv_reader = csv.DictReader(io.StringIO(content))

        # Validate CSV headers
        required_headers = {'node_id', 'node_name', 'parent_id'}
        if not required_headers.issubset(set(csv_reader.fieldnames or [])):
            return jsonify({"error": f"CSV must contain headers: {', '.join(required_headers)}"}), 400

        conn = get_db()
        cursor = conn.cursor()

        # Security: Create backup with safe SQL identifier
        backup_suffix = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"clades_backup_before_restore_{backup_suffix}"

        # Use psycopg2.sql.Identifier to safely escape table name
        cursor.execute(sql.SQL("""
            CREATE TABLE {} AS 
            SELECT * FROM clades
        """).format(sql.Identifier(backup_name)))

        # Clear existing data
        cursor.execute("TRUNCATE TABLE clades CASCADE")

        # Insert data from CSV with validation
        rows_imported = 0
        for row in csv_reader:
            node_id = row['node_id'].strip()
            node_name = row['node_name'].strip()
            parent_id = row['parent_id'].strip() if row['parent_id'].strip() else None
            description = row.get('description', '').strip() or None
            traits = row.get('traits', '').strip() or None

            # Security: Validate inputs
            if not validate_node_id(node_id):
                cursor.execute("ROLLBACK")
                return jsonify({"error": f"Invalid node_id format: {node_id[:50]}"}), 400

            if not validate_node_name(node_name):
                cursor.execute("ROLLBACK")
                return jsonify({"error": f"Invalid node_name format"}), 400

            if parent_id and not validate_node_id(parent_id):
                cursor.execute("ROLLBACK")
                return jsonify({"error": f"Invalid parent_id format: {parent_id[:50]}"}), 400

            cursor.execute("""
                INSERT INTO clades (node_id, node_name, parent_id, description, traits)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (node_id) DO UPDATE SET
                    node_name = EXCLUDED.node_name,
                    parent_id = EXCLUDED.parent_id,
                    description = EXCLUDED.description,
                    traits = EXCLUDED.traits
            """, (node_id, node_name, parent_id, description, traits))

            rows_imported += 1

        conn.commit()
        cursor.close()
        conn.close()

        # Reload in-memory state
        load_db()

        audit_log('RESTORE_DATABASE', f'File={file.filename}, Rows={rows_imported:,}, Backup={backup_name}', status='SUCCESS')

        return jsonify({
            "message": f"Database restored from CSV: {rows_imported:,} nodes imported",
            "backup": backup_name
        })

    except Exception as e:
        error_msg = str(e)
        audit_log('RESTORE_DATABASE', f'ERROR={error_msg}', status='ERROR')
        return jsonify({"error": f"{sanitize_error(error_msg)}\n\nDetails: {error_msg}"}), 500

@app.route("/api/delete/<node_id>", methods=["POST"])
@require_auth('editor')
def api_delete(node_id):
    """Delete a node from the database"""
    if node_id not in state:
        return jsonify({"error": "not found"}), 404

    # Check if node has children
    if parent_children.get(node_id):
        return jsonify({"error": "Cannot delete a node that has children"}), 400

    parent_id = str(state[node_id].get("parent", "") or "")
    if not parent_id:
        return jsonify({"error": "Cannot delete root node"}), 400

    name = (state[node_id].get("name") or "").strip()

    try:
        # Delete from PostgreSQL
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM clades WHERE node_id = %s", (node_id,))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        audit_log('DELETE_NODE', f'Name={name}, ID={node_id[:8]}... ERROR={str(e)}', status='ERROR')
        return jsonify({"error": str(e)}), 500

    # Update in-memory state
    if parent_id in parent_children:
        try:
            parent_children[parent_id].remove(node_id)
        except ValueError:
            pass

    name_to_id.pop(name.lower(), None)
    parent_children.pop(node_id, None)
    state.pop(node_id, None)
    _rebuild_homo_path()

    audit_log('DELETE_NODE', f'Name={name}, ID={node_id[:8]}...', status='SUCCESS')

    return jsonify({"deleted_id": node_id, "deleted_name": name, "parent_id": parent_id})

@app.before_request
def before_request():
    """Track request start time"""
    import time
    request.start_time = time.time()

@app.after_request
def add_security_headers(resp):
    """Add security headers and log request timing"""
    import time

    # Calculate request duration
    if hasattr(request, 'start_time'):
        duration = time.time() - request.start_time
        duration_ms = duration * 1000

        # Log request with timing
        user = get_current_user() or 'anonymous'
        logger.info(f"REQUEST: {request.method} {request.path} | User: {user} | Status: {resp.status_code} | Duration: {duration_ms:.2f}ms")

    # Cache control
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'

    # Security headers
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # CSP - adjust as needed for your application
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    return resp

# ============================================================================
# STARTUP: Load database and users when module is imported (for Gunicorn)
# ============================================================================
print("\n" + "="*60)
print("Phylogeny Explorer - revised data")
print("="*60)

# Load phylogenetic tree from database
load_db()

# Load users from database
USERS = load_users_from_db()

logger.info("="*60)
logger.info("MODULE LOADED - DATABASE READY")
logger.info(f"Total nodes loaded: {len(state):,}")
logger.info(f"Path to Homo sapiens: {len(homo_path_ids)} nodes")
logger.info(f"Users loaded: {len(USERS)}")
logger.info("="*60)

# ============================================================================
# Main function for standalone execution
# ============================================================================
def main():
    global USERS

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("Phylogeny Explorer - revised data")
    print("="*60)

    # Database and users already loaded at module import
    # Just log startup info

    logger.info("="*60)
    logger.info("SERVER STARTUP (standalone mode)")
    logger.info(f"Host: {args.host}:{args.port}")
    logger.info(f"Total nodes loaded: {len(state):,}")
    logger.info(f"Path to Homo sapiens: {len(homo_path_ids)} nodes")
    logger.info(f"Users loaded: {len(USERS)}")
    logger.info(f"Session timeout: {app.config['PERMANENT_SESSION_LIFETIME']} seconds")
    logger.info(f"Audit logging: ENABLED")
    logger.info("="*60)

    print(f"\nOpen: http://{args.host}:{args.port}")
    print("="*60 + "\n")
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()
