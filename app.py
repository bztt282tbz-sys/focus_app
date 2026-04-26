
import os
import json
import base64
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session, abort
from flask_limiter import Limiter
from flask_talisman import Talisman
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from functools import wraps
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION ---

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
RP_ID = os.environ.get('RP_ID')
RP_NAME = "Focus App"
ORIGIN = os.environ.get('ORIGIN')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

if not app.config['SECRET_KEY']:
    raise RuntimeError("FATAL: SECRET_KEY is not set.")


# --- EXTENSIONS ---

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net' # If using Bootstrap CDN
    ]
}
Talisman(app, force_https=True, content_security_policy=csp)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

# --- MODELS ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    temp_username = db.Column(db.String(50), nullable=True)
    credential_id = db.Column(db.LargeBinary, nullable=True)
    public_key = db.Column(db.LargeBinary, nullable=True)
    sign_count = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True)
    value = db.Column(db.Boolean, default=True)

def get_setting(key):
    setting = SystemSetting.query.filter_by(key=key).first()
    return setting.value if setting else True

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('home.html', title="Home")

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    reg_enabled = get_setting('registration_enabled')
    login_enabled = get_setting('login_enabled')
    return render_template('admin.html', users=users, reg_enabled=reg_enabled, login_enabled=login_enabled)

@app.route('/admin/toggle_user/<int:user_id>')
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot deactivate yourself!", "danger")
    else:
        user.is_active = not user.is_active
        db.session.commit()
        flash(f"User {user.username} status updated.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/register', methods=['GET'])
@limiter.limit("5 per hour")
def register():
    if not get_setting('registration_enabled'):
        flash("Registration is currently disabled.", "warning")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/generate-register', methods=['POST'])
def generate_register():
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=os.urandom(16),
        user_name="anonymous",
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED
        )
    )
    session['reg_challenge'] = options.challenge
    return options_to_json(options)

@app.route('/verify-register', methods=['POST'])
def verify_register():
    try:
        # Verify the WebAuthn registration response
        verification = verify_registration_response(
            credential=request.json,
            expected_challenge=session.get('reg_challenge'),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        ) 
        
        # Determine if this is the first user (admin)
        is_first = User.query.count() == 0 
        
        # Create and save the new user
        new_user = User(
            username=f"User_{os.urandom(4).hex()}",
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            is_admin=is_first
        ) 
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please login.", "success") 
        return jsonify({"status": "ok", "redirect": url_for('login')})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/generate-auth', methods=['POST'])
def generate_auth():
    users = User.query.filter_by(is_active=True).all()
    if not users:
        return jsonify({"error": "No registered users."}), 400
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=u.credential_id)
        for u in users if u.credential_id
    ]
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED
    )
    session['auth_challenge'] = options.challenge
    return options_to_json(options)

@app.route('/verify-auth', methods=['POST'])
def verify_auth():
    try:
        raw_id = base64url_to_bytes(request.json.get("rawId"))
        user = User.query.filter_by(credential_id=raw_id).first()
        if not user or not user.is_active:
            return jsonify({"error": "Invalid credential."}), 403
        if not get_setting('login_enabled') and not user.is_admin:
            return jsonify({"error": "Login temporarily disabled."}), 403
        verification = verify_authentication_response(
            credential=request.json,
            expected_challenge=session.get('auth_challenge'),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=user.public_key,
            credential_current_sign_count=user.sign_count
        )
        user.sign_count = verification.new_sign_count
        db.session.commit()
        login_user(user)
        return jsonify({"status": "ok", "redirect": url_for('dashboard')})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/login', methods=['GET'])
@limiter.limit("5 per hour")
def login():
    return render_template('login.html')

@app.route('/dashboard')
@limiter.limit("5 per second")
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

