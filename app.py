import os
import json
import base64
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session, abort
from datetime import datetime, timezone, timedelta
import calendar
from flask_limiter import Limiter
from flask_talisman import Talisman
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
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
date = datetime.now(timezone.utc)

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
    'script-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net'
    ],
    'style-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
        '\'unsafe-inline\''
    ],
    'img-src': [
        '\'self\'',
        'data:'
    ]
}

Talisman(
    app, 
    force_https=True, 
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src']
)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    is_onboarded = db.Column(db.Boolean, default=False)
    security_preference = db.Column(db.String(20), default="Normal")
    credential_id = db.Column(db.LargeBinary, nullable=True)
    public_key = db.Column(db.LargeBinary, nullable=True)
    sign_count = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    prf_salt = db.Column(db.LargeBinary, nullable=True)

class SystemSettingBool(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(100))
    key = db.Column(db.String(50), unique=True)
    value = db.Column(db.Boolean, default=True)
    expected_value = db.Column(db.Boolean, default=True)
    implemented = db.Column(db.Boolean, default=False)

class UsersTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    label = db.Column(db.String(65536), nullable=False)
    comment = db.Column(db.String(65536))
    importance = db.Column(db.Integer, default=1) 
    complexity = db.Column(db.Integer, default=2) 
    date_created = db.Column(db.DateTime, default=db.func.now())
    date_start = db.Column(db.DateTime, nullable=False, index=True)
    date_due = db.Column(db.DateTime, nullable=True, index=True)
    is_hidden = db.Column(db.Boolean, default=False)
    date_hidden = db.Column(db.DateTime, nullable=True) 
    date_deletion_requested = db.Column(db.DateTime, nullable=True)
    date_deleted = db.Column(db.DateTime, nullable=True)
    author = db.relationship('User', backref=db.backref('tasks', lazy=True))
    progress_entries = db.relationship('TaskProgressEntry', backref='task', lazy=True, cascade="all, delete-orphan")
    @property
    def progress(self):
        if self.complexity <= 0: return 100
        # Sum all related progress entries
        done = sum(entry.points_completed for entry in self.progress_entries)
        return min(int((done / self.complexity) * 100), 100)

    @property
    def completed(self):
        return self.progress >= 100
    
class TaskProgressEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('users_task.id'), nullable=False, index=True)
    points_completed = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(280), nullable=True) 
    date_logged = db.Column(db.DateTime, default=db.func.now())

def get_setting(key):
    setting = SystemSettingBool.query.filter_by(key=key).first()
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

def onboarding_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and not current_user.is_onboarded:
            return redirect(url_for('onboarding'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('home.html', title="Home")

@app.route('/about')
def about():
    return render_template('about.html', title="About")

@app.route('/onboarding', methods=['GET', 'POST'])
@login_required
def onboarding():
    if current_user.is_onboarded:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        security = request.form.get('security_preference')
        if not username or len(username) < 3:
            flash("Please enter a valid username (min 3 chars).", "danger")
            return render_template('onboarding.html')
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template('onboarding.html')
        current_user.username = username
        current_user.security_preference = security
        current_user.is_onboarded = True
        db.session.commit()
        flash("Profile completed!", "success")
        return redirect(url_for('dashboard'))
    return render_template('onboarding.html')

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    settings = SystemSettingBool.query.all()
    return render_template('admin.html', users=users, settings=settings)

@app.route('/admin/toggle_user/<int:user_id>', methods=['POST'])
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
        flash("Registration is currently disabled for maintenance.", "warning")
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
        verification = verify_registration_response(
            credential=request.json,
            expected_challenge=session.get('reg_challenge'),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        ) 
        user_salt = os.urandom(32)
        is_first = User.query.count() == 0 
        new_user = User(
            username=f"User_{os.urandom(4).hex()}",
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            is_admin=is_first,
            prf_salt=user_salt
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
    user_data = {
        "options": options_to_json(options),
        "salts": { base64.b64encode(u.credential_id).decode(): base64.b64encode(u.prf_salt).decode() 
                   for u in users if u.prf_salt }
    }
    return jsonify(user_data)

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

@app.route('/tasks/<int:task_id>/log_progress', methods=['POST'])
@login_required
@onboarding_required
def log_task_progress(task_id):
    task = UsersTask.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)

    points = int(request.form.get('points', 0))
    comment = request.form.get('update_comment') # Capture the comment
    current_done = sum(entry.points_completed for entry in task.progress_entries)

    if points > 0 and (current_done + points) <= task.complexity:
        # Save the comment along with the points
        new_entry = TaskProgressEntry(
            task_id=task.id, 
            points_completed=points, 
            comment=comment
        )
        db.session.add(new_entry)
        db.session.commit()
        flash(f"Progress updated!", "success")
    else:
        flash("Invalid progress amount.", "danger")
        
    return redirect(url_for('view_task', task_id=task.id))

@app.route('/admin/user/<int:user_id>')
@login_required
@admin_required
def view_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    # We can also fetch their task count or last activity here
    task_stats = {
        "total": UsersTask.query.filter_by(user_id=user.id).count(),
        "active": UsersTask.query.filter_by(user_id=user.id, is_hidden=False).count()
    }
    return render_template('user_detail.html', user=user, stats=task_stats, title=f"Manage {user.username}")

@app.route('/admin/toggle_setting/<string:setting_key>', methods=['POST'])
@login_required
@onboarding_required
@admin_required
def toggle_setting(setting_key):
    if setting_key not in ['registration_enabled', 'login_enabled', 'api_enabled']:
        abort(400)
    setting = SystemSettingBool.query.filter_by(key=setting_key).first()
    if not setting:
        setting = SystemSettingBool(key=setting_key, value=False)
        db.session.add(setting)
    else:
        setting.value = not setting.value
    db.session.commit()
    status = "enabled" if setting.value else "disabled"
    flash(f"System setting '{setting_key}' has been {status}.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/tasks/<int:task_id>', methods=['GET'])
@login_required
@onboarding_required
def view_task(task_id):
    task = UsersTask.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
        
    completed_points = sum(entry.points_completed for entry in task.progress_entries)
    remaining_points = max(0, task.complexity - completed_points)
    
    return render_template('task_detail.html', 
                       task=task, 
                       completed_points=completed_points, 
                       remaining_points=remaining_points, 
                       title=f"Task: {task.label}")


@app.route('/tasks/new', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@login_required
@onboarding_required
def new_task():
    if request.method == 'POST':
        label = request.form.get('label')
        comment = request.form.get('comment')
        importance = int(request.form.get('importance', 1))
        complexity = int(request.form.get('complexity', 2))
        date_start_str = request.form.get('date_start')
        date_due_str = request.form.get('date_due')

        if not label or len(label) > 100:
            flash("Task label is required and must be under 100 characters.", "danger")
            return redirect(url_for('new_task'))

        date_start = datetime.strptime(date_start_str, '%Y-%m-%d') if date_start_str else datetime.utcnow()
        date_due = datetime.strptime(date_due_str, '%Y-%m-%d') if date_due_str else None

        task = UsersTask(
            user_id=current_user.id,
            label=label,
            comment=comment,
            importance=importance,
            complexity=complexity,
            date_start=date_start,
            date_due=date_due
        )
        
        db.session.add(task)
        db.session.commit()
        
        flash("Task created successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('new_task.html', title="New Task")

@app.route('/login', methods=['GET'])
@limiter.limit("5 per hour")
def login():
    return render_template('login.html')

@app.route('/dashboard')
@login_required
@onboarding_required
def dashboard():
    # 1. Subquery to calculate current progress for all tasks
    progress_subquery = db.session.query(
        TaskProgressEntry.task_id,
        func.sum(TaskProgressEntry.points_completed).label('total_done')
    ).group_by(TaskProgressEntry.task_id).subquery()

    # 2. Base query for this user's tasks
    base_query = UsersTask.query.outerjoin(
        progress_subquery, UsersTask.id == progress_subquery.c.task_id
    ).filter(
        UsersTask.user_id == current_user.id,
        UsersTask.is_hidden == False,
        UsersTask.date_deleted == None
    )

    # FIX: Get current UTC time and strip the time components for a "today" comparison
    # Use datetime.now(timezone.utc) instead of datetime.utcnow()
    now_utc = datetime.now(timezone.utc)
    today_dt = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # 3. Filter for Focus List
    focus_tasks = base_query.filter(
        func.coalesce(progress_subquery.c.total_done, 0) < UsersTask.complexity,
        (UsersTask.date_due == None) | (UsersTask.date_due >= today_dt)
    ).order_by(UsersTask.importance.desc()).all()

    # 4. Filter for Past/Completed List
    past_tasks = base_query.filter(
        (func.coalesce(progress_subquery.c.total_done, 0) >= UsersTask.complexity) |
        (UsersTask.date_due < today_dt)
    ).all()

    return render_template(
        'dashboard.html',
        tasks=focus_tasks,
        past_tasks=past_tasks,
        task_count=len(focus_tasks),
        today=now_utc.date()
    )

@app.route('/calendar')
@login_required
@onboarding_required
def calendar_view():
    # Use timezone.utc correctly
    now_utc = datetime.now(timezone.utc)
    year = request.args.get('year', now_utc.year, type=int)
    month = request.args.get('month', now_utc.month, type=int)

    cal = calendar.monthcalendar(year, month)
    
    # Calculate date range for the query
    start_date = datetime(year, month, 1)
    if month == 12:
        end_date = datetime(year + 1, 1, 1)
    else:
        end_date = datetime(year, month + 1, 1)
        
    # Ensure UsersTask is correctly referenced
    tasks = UsersTask.query.filter(
        UsersTask.user_id == current_user.id,
        UsersTask.is_hidden == False,
        UsersTask.date_deleted == None,
        UsersTask.date_due >= start_date,
        UsersTask.date_due < end_date
    ).all()
    
    task_counts = {}
    for t in tasks:
        if t.date_due:
            # Handle both offset-naive and offset-aware comparisons if necessary
            day = t.date_due.day
            task_counts[day] = task_counts.get(day, 0) + 1
            
    month_name = calendar.month_name[month]
    
    return render_template('calendar.html', cal=cal, month=month, year=year, month_name=month_name, task_counts=task_counts, title="Calendar")

@app.route('/calendar/<date_str>')
@login_required
@onboarding_required
def calendar_day(date_str):
    try:
        target_date = datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        abort(400)
        
    next_day = target_date + timedelta(days=1)
    
    # Using the existing progress logic from your dashboard to calculate percentages
    # Assuming TaskProgressEntry is the correct model name from your schema
    progress_subquery = db.session.query(
        TaskProgressEntry.task_id,
        func.sum(TaskProgressEntry.points_completed).label('total_done')
    ).group_by(TaskProgressEntry.task_id).subquery()
    
    tasks = UsersTask.query.outerjoin(
        progress_subquery, UsersTask.id == progress_subquery.c.task_id
    ).filter(
        UsersTask.user_id == current_user.id,
        UsersTask.is_hidden == False,
        UsersTask.date_deleted == None,
        UsersTask.date_due >= target_date,
        UsersTask.date_due < next_day
    ).all()
    
    # Calculating progress for each task object to avoid template errors
    for task in tasks:
        task.progress = min(100, int((task.total_done or 0) / task.points_required * 100)) if task.points_required > 0 else 0
    
    return render_template('calendar_day.html', tasks=tasks, date_str=date_str, target_date=target_date, title=f"Tasks for {date_str}")

@app.route('/search')
@login_required
@onboarding_required
def search_page():
    tasks = UsersTask.query.filter_by(
        user_id=current_user.id,
        is_hidden=False,
        date_deleted=None
    ).order_by(UsersTask.date_due.desc()).all()
    return render_template('search.html', tasks=tasks, title="Search Tasks")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))