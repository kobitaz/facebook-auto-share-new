"""
Facebook Auto Share - Web Application with Authentication
"""

import json
import re
import asyncio
import os
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from cookie_manager import CookieManager
from facebook_sharer import FacebookSharer
from cookie_getter import get_cookie_json
from models import db, User, UserAccessLog, ShareHistory

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "fb_auto_share_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")  # Use the DATABASE_URL
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Suppress warning

# Initialize database
db.init_app(app)

# Function to check and update the database schema
def update_database_schema():
    """Check and update database schema as needed"""
    from sqlalchemy import inspect
    
    # Get inspector
    inspector = inspect(db.engine)
    
    # Check if tables exist
    if not inspector.has_table('users'):
        # Create all tables from scratch
        db.create_all()
        print("Database tables created successfully!")
        User.create_admin()
        print("Admin user created!")
        return
    
    # Get existing columns in users table
    columns = {col['name'] for col in inspector.get_columns('users')}
    
    # Check if session_token column exists in users table
    if 'session_token' not in columns:
        # Add the session_token column
        with db.engine.connect() as conn:
            conn.execute(db.text("ALTER TABLE users ADD COLUMN session_token VARCHAR(256)"))
            conn.commit()
            print("Added session_token column to users table")
    
    # Check if share_history table exists
    if not inspector.has_table('share_history'):
        # Create share_history table
        with db.engine.connect() as conn:
            conn.execute(db.text("""
                CREATE TABLE share_history (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    task_id VARCHAR(100) UNIQUE NOT NULL,
                    post_url VARCHAR(512) NOT NULL,
                    share_count INTEGER NOT NULL,
                    delay INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    current_count INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    status VARCHAR(20) DEFAULT 'running',
                    messages TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """))
            conn.commit()
            print("Created share_history table")
    
    # Check if action column in user_access_logs needs to be expanded
    columns = {col['name']: col for col in inspector.get_columns('user_access_logs')}
    if 'action' in columns:
        # Alter the action column to increase size
        with db.engine.connect() as conn:
            conn.execute(db.text("ALTER TABLE user_access_logs ALTER COLUMN action TYPE VARCHAR(255)"))
            conn.commit()
            print("Expanded action column in user_access_logs table")
            
# Update database schema
with app.app_context():
    update_database_schema()

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = "Please log in to access this page."
login_manager.session_protection = "strong"
# Set cookie expiration to 30 days
app.config['REMEMBER_COOKIE_DURATION'] = 60 * 60 * 24 * 30  # 30 days

# Function to log user activity
def log_user_activity(user_id, action, ip_address=None, user_agent=None):
    """Log user activity for tracking purposes"""
    try:
        if user_agent is None and request:
            user_agent = request.user_agent.string
            
        ip_addr = ip_address or request.remote_addr
        
        log = UserAccessLog(
            user_id=user_id,
            action=action,
            ip_address=ip_addr,
            user_agent=user_agent
        )
        
        db.session.add(log)
        db.session.commit()
        return True
    except Exception as e:
        print(f"Error logging user activity: {str(e)}")
        return False

@login_manager.user_loader
def load_user(user_id):
    """Load user from database"""
    user = User.query.get(int(user_id))
    if user and user.is_blocked:
        return None  # Return None for blocked users to force logout
    return user

# Global variables to store sharing status
share_results = {}
current_tasks = {}

class WebSharerUI:
    """Adapter class to provide a web UI interface for the Facebook sharer"""
    
    def __init__(self, task_id):
        self.task_id = task_id
        self.messages = []
        share_results[task_id] = {
            "status": "initializing",
            "messages": self.messages,
            "current": 0,
            "total": 0,
            "success_count": 0,
            "completed": False
        }
    
    def show_info(self, message):
        """Display info message"""
        self.messages.append({"type": "info", "message": message})
        
    def show_success(self, message):
        """Display success message"""
        self.messages.append({"type": "success", "message": message})
        
    def show_error(self, message):
        """Display error message"""
        self.messages.append({"type": "error", "message": message})
        
    def show_warning(self, message):
        """Display warning message"""
        self.messages.append({"type": "warning", "message": message})
        
    def show_status(self, message):
        """Display status message"""
        self.messages.append({"type": "status", "message": message})
    
    def init_progress_bar(self, total):
        """Initialize progress tracking"""
        share_results[self.task_id]["total"] = total
        share_results[self.task_id]["current"] = 0
        share_results[self.task_id]["status"] = "running"
    
    def update_sharing_status(self, current, total, post_id, success=None):
        """Update sharing progress status"""
        share_results[self.task_id]["current"] = current
        
        if success is True:
            share_results[self.task_id]["success_count"] += 1
            self.show_success(f"Share {current}/{total} for post {post_id} successful")
        elif success is False:
            self.show_error(f"Share {current}/{total} for post {post_id} failed")
    
    def show_delay_animation(self, delay_seconds):
        """Show delay info"""
        self.show_info(f"Waiting {delay_seconds}s before next share...")
    
    def show_summary(self, success_count, total_count):
        """Show summary of sharing process"""
        share_results[self.task_id]["completed"] = True
        share_results[self.task_id]["status"] = "completed"
        
        success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
        
        summary = f"Completed: {success_count}/{total_count} shares successful ({success_rate:.1f}%)"
        self.show_info(summary)
        
        if success_rate == 100:
            self.show_success("All shares completed successfully!")
        elif success_rate > 0:
            self.show_warning("Some shares were successful")
        else:
            self.show_error("All shares failed! Please check your cookie and try again")


async def process_share_task(task_id, cookie_json, post_url, share_count, delay):
    """Process the sharing task asynchronously"""
    ui = WebSharerUI(task_id)
    history = None
    
    try:
        # Get the history record
        history = ShareHistory.query.filter_by(task_id=task_id).first()
        
        # Convert JSON to cookie string
        cookie_manager = CookieManager()
        cookie_string = cookie_manager.json_to_string(cookie_json)
        
        # Validate cookie string
        if not cookie_manager.validate_cookie(cookie_string):
            ui.show_error("Invalid cookie content. Make sure it contains required Facebook tokens (c_user, xs).")
            share_results[task_id]["status"] = "failed"
            share_results[task_id]["completed"] = True
            
            # Update history if it exists
            if history:
                history.status = "failed"
                history.messages = json.dumps(ui.messages)
                db.session.commit()
            return
        
        # Check if the cookie is live/valid
        ui.show_status("Checking if cookie is valid...")
        
        if not cookie_manager.check_cookie_live(cookie_string):
            ui.show_warning("Cookie might be invalid or expired, but proceeding anyway")
        else:
            ui.show_success("Cookie is valid!")
        
        # Validate post URL
        if not post_url.startswith("https://www.facebook.com/"):
            ui.show_warning("Post URL does not start with 'https://www.facebook.com/'")
        
        # Extract post ID for display
        post_id_match = re.search(r'facebook\.com/(?:.*?/)?(\d+|permalink\.php\?.*?id=\d+|story\.php\?.*?id=\d+)', post_url)
        if post_id_match:
            post_id = post_id_match.group(1)
            ui.show_info(f"Detected post ID: {post_id}")
        else:
            ui.show_warning("Could not extract post ID from URL")
            post_id = post_url
        
        # Initialize Facebook sharer
        sharer = FacebookSharer(cookie_string, ui)
        
        # Run the share process
        ui.show_info(f"Starting to share post {share_count} times with {delay}s delay")
        ui.show_info(f"Post URL: {post_url}")
        
        # Execute the sharing process
        await sharer.share_post(post_url, share_count, delay)
        
        # Update history record when completed
        if history:
            history.status = "completed"
            history.completed_at = datetime.utcnow()
            history.current_count = share_results[task_id]["current"]
            history.success_count = share_results[task_id]["success_count"]
            history.messages = json.dumps(ui.messages)
            db.session.commit()
        
    except Exception as e:
        ui.show_error(f"An unexpected error occurred: {str(e)}")
        share_results[task_id]["status"] = "failed"
        share_results[task_id]["completed"] = True
        
        # Update history if it exists
        if history:
            history.status = "failed"
            history.messages = json.dumps(ui.messages)
            db.session.commit()


def run_async_task(task_id, cookie_json, post_url, share_count, delay):
    """Run async task in a separate thread"""
    with app.app_context():
        # Create application context for this thread
        asyncio.run(process_share_task(task_id, cookie_json, post_url, share_count, delay))
        if task_id in current_tasks:
            del current_tasks[task_id]


@app.route('/')
def index():
    """Main page - redirects to login if not authenticated"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user is not None and user.verify_password(password):
            # Check if user is blocked
            if user.is_blocked:
                flash('Your account has been blocked. Please contact the administrator.', 'error')
                return render_template('login.html')
                
            # Update user login statistics
            user.last_login_ip = request.remote_addr
            user.last_login_at = datetime.utcnow()
            user.login_count += 1
            db.session.commit()
            
            # Log user activity
            log_user_activity(user_id=user.id, action="Login", ip_address=request.remote_addr)
            
            # Login the user and remember them (persistent login)
            login_user(user, remember=True)
            
            # Generate a session token for additional security
            import secrets
            session_token = secrets.token_hex(32)
            user.session_token = session_token
            db.session.commit()
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.')
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if username exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return render_template('register.html')
        
        # Create new user
        new_user = User()
        new_user.username = username
        new_user.password = password
        new_user.last_login_ip = request.remote_addr
        new_user.last_login_at = datetime.utcnow()
        new_user.login_count = 1
        db.session.add(new_user)
        db.session.commit()
        
        # Log user registration
        log_user_activity(user_id=new_user.id, action="User registration", ip_address=request.remote_addr)
        
        flash('Account created successfully! You can now log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page after login"""
    # Check if user is blocked
    if current_user.is_blocked:
        logout_user()
        flash('Your account has been blocked. Please contact the administrator.', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html')


@app.route('/history')
@login_required
def sharing_history():
    """View sharing history"""
    # Check if user is blocked
    if current_user.is_blocked:
        logout_user()
        flash('Your account has been blocked. Please contact the administrator.', 'error')
        return redirect(url_for('login'))
    
    # Get user's share history
    history = ShareHistory.query.filter_by(user_id=current_user.id).order_by(ShareHistory.created_at.desc()).all()
    
    # Log user activity
    log_user_activity(current_user.id, "Viewed sharing history", request.remote_addr)
    
    return render_template('history.html', history=history)


@app.route('/admin')
@login_required
def admin_panel():
    """Admin panel to manage users and view access logs"""
    # Check if user is admin
    if not current_user.is_admin:
        flash('You do not have permission to access the admin panel.', 'error')
        return redirect(url_for('dashboard'))
        
    # Get all users
    users = User.query.all()
    
    # Get recent logs
    logs = UserAccessLog.query.order_by(UserAccessLog.accessed_at.desc()).limit(50).all()
    
    return render_template('admin.html', users=users, logs=logs)
    

@app.route('/admin/user/<int:user_id>/logs')
@login_required
def view_user_logs(user_id):
    """View logs for a specific user"""
    # Check if user is admin
    if not current_user.is_admin:
        flash('You do not have permission to access the admin panel.', 'error')
        return redirect(url_for('dashboard'))
        
    # Get user
    user = User.query.get_or_404(user_id)
    
    # Get user logs
    logs = UserAccessLog.query.filter_by(user_id=user_id).order_by(UserAccessLog.accessed_at.desc()).all()
    
    return render_template('user_logs.html', user=user, logs=logs)
    

@app.route('/admin/user/<int:user_id>/toggle_block')
@login_required
def toggle_user_block(user_id):
    """Toggle block status of a user"""
    # Check if user is admin
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
        
    # Get user
    user = User.query.get_or_404(user_id)
    
    # Don't allow blocking other admins
    if user.is_admin and user.id != current_user.id:
        flash('You cannot block other admin users.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Toggle block status
    user.is_blocked = not user.is_blocked
    db.session.commit()
    
    # Log the action
    action = f"{'Blocked' if user.is_blocked else 'Unblocked'} user"
    log_user_activity(current_user.id, action, request.remote_addr)
    
    flash(f"User has been {'blocked' if user.is_blocked else 'unblocked'}.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/toggle_premium')
@login_required
def toggle_user_premium(user_id):
    """Toggle premium status of a user"""
    # Check if user is admin
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
        
    # Get user
    user = User.query.get_or_404(user_id)
    
    # Toggle premium status
    user.is_premium = not user.is_premium
    db.session.commit()
    
    # Log the action
    action = f"{'Added' if user.is_premium else 'Removed'} premium status"
    log_user_activity(current_user.id, action, request.remote_addr)
    
    flash(f"User premium status has been {'enabled' if user.is_premium else 'disabled'}.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/cookie-getter')
@login_required
def cookie_getter():
    """Cookie Getter page"""
    # Check if user is blocked
    if current_user.is_blocked:
        logout_user()
        flash('Your account has been blocked. Please contact the administrator.', 'error')
        return redirect(url_for('login'))
    
    # Log user activity
    log_user_activity(current_user.id, "Accessed cookie getter", request.remote_addr)
    
    return render_template('cookie_getter.html')


@app.route('/api/get_cookie', methods=['POST'])
@login_required
def get_cookie_api():
    """API endpoint to get Facebook cookies from login credentials"""
    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"success": False, "error": "Username and password are required"}), 400
        
        # Log user activity
        log_user_activity(current_user.id, "Generated cookie", request.remote_addr)
        
        result = get_cookie_json(username, password)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/start_sharing', methods=['POST'])
@login_required
def start_sharing():
    """API endpoint to start a sharing task"""
    try:
        # Check if user is blocked
        if current_user.is_blocked:
            return jsonify({
                "success": False,
                "error": "Your account has been blocked. Please contact the administrator."
            }), 403
            
        data = request.json
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        cookie_json = data.get('cookie')
        post_url = data.get('post_url')
        share_count = int(data.get('share_count', 1))
        delay = int(data.get('delay', 5))
        
        # Check if required fields are provided
        if not cookie_json or not post_url:
            return jsonify({"success": False, "error": "Cookie and post URL are required"}), 400
        
        # Check share count limits based on user status
        max_shares = 100000 if current_user.is_premium else 1000
        if share_count > max_shares:
            return jsonify({
                "success": False, 
                "error": f"Free users can only share up to {max_shares} times per session. Upgrade to premium for more."
            }), 403
        
        # Create a unique task ID for this sharing operation
        task_id = f"{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Create a ShareHistory record
        share_history = ShareHistory()
        share_history.user_id = current_user.id
        share_history.task_id = task_id
        share_history.post_url = post_url
        share_history.share_count = share_count
        share_history.delay = delay
        share_history.status = 'running'
        share_history.messages = json.dumps([])  # Empty messages initially
        db.session.add(share_history)
        db.session.commit()
        
        # Start the sharing task in a separate thread
        thread = threading.Thread(
            target=run_async_task, 
            args=(task_id, cookie_json, post_url, share_count, delay)
        )
        thread.daemon = True
        thread.start()
        
        # Store the task reference
        current_tasks[task_id] = thread
        
        # Log the sharing activity
        log_user_activity(
            current_user.id, 
            f"Started sharing task for {post_url} ({share_count} shares)",
            request.remote_addr
        )
        
        return jsonify({
            "success": True,
            "task_id": task_id,
            "message": "Sharing task started successfully"
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/check_share_status/<task_id>')
@login_required
def check_share_status(task_id):
    """API endpoint to check the status of a sharing task"""
    if task_id in share_results:
        # Update history record with latest status
        update_share_history(task_id)
        
        return jsonify({
            "success": True,
            "result": share_results[task_id]
        })
    else:
        # Check if we have a history record for this task
        history = ShareHistory.query.filter_by(task_id=task_id).first()
        if history:
            # Return the stored information
            return jsonify({
                "success": True,
                "result": {
                    "status": history.status,
                    "current": history.current_count,
                    "total": history.share_count,
                    "completed": history.status in ["completed", "failed", "paused"],
                    "success_count": history.success_count,
                    "messages": json.loads(history.messages) if history.messages else []
                }
            })
        
        return jsonify({
            "success": False,
            "error": "Task not found or expired"
        }), 404

def update_share_history(task_id):
    """Update the share history record with current status"""
    if task_id not in share_results:
        return
        
    history = ShareHistory.query.filter_by(task_id=task_id).first()
    if not history:
        return
        
    # Update the history record with current status
    history.current_count = share_results[task_id]["current"]
    history.success_count = share_results[task_id]["success_count"]
    history.messages = json.dumps(share_results[task_id]["messages"])
    
    if share_results[task_id]["completed"]:
        history.status = "completed"
        history.completed_at = datetime.utcnow()
        
    db.session.commit()

@app.route('/api/pause_sharing/<task_id>')
@login_required
def pause_sharing(task_id):
    """API endpoint to pause a running sharing task"""
    # Check if task exists
    history = ShareHistory.query.filter_by(task_id=task_id, user_id=current_user.id).first()
    if not history:
        return jsonify({
            "success": False,
            "error": "Task not found"
        }), 404
        
    # Check if task is already completed or paused
    if history.status in ["completed", "failed", "paused"]:
        return jsonify({
            "success": False,
            "error": f"Task is already {history.status}"
        }), 400
        
    # Update status to paused
    history.status = "paused"
    db.session.commit()
    
    # If task is in memory, update its status too
    if task_id in share_results:
        share_results[task_id]["status"] = "paused"
        share_results[task_id]["completed"] = True
        
    # Log the action
    log_user_activity(
        current_user.id,
        f"Paused sharing task {task_id}",
        request.remote_addr
    )
    
    return jsonify({
        "success": True,
        "message": "Task paused successfully"
    })


@app.route('/api/resume_sharing/<task_id>', methods=['POST'])
@login_required
def resume_sharing(task_id):
    """API endpoint to resume a paused sharing task"""
    try:
        # Check if task exists
        history = ShareHistory.query.filter_by(task_id=task_id, user_id=current_user.id).first()
        if not history:
            return jsonify({
                "success": False,
                "error": "Task not found"
            }), 404
            
        # Check if task is paused
        if history.status != "paused":
            return jsonify({
                "success": False,
                "error": f"Task is not paused, it is {history.status}"
            }), 400
            
        # Get the cookie JSON from the request
        data = request.json
        if not data or not data.get('cookie'):
            return jsonify({
                "success": False,
                "error": "Cookie data is required to resume sharing"
            }), 400
            
        cookie_json = data.get('cookie')
        
        # Remaining shares to process
        remaining_count = history.share_count - history.current_count
        
        if remaining_count <= 0:
            # Nothing left to do
            history.status = "completed"
            db.session.commit()
            return jsonify({
                "success": False,
                "error": "This task has already completed all shares"
            }), 400
            
        # Update status to running
        history.status = "running"
        db.session.commit()
        
        # Start a new sharing process for the remaining shares
        thread = threading.Thread(
            target=run_async_task, 
            args=(task_id, cookie_json, history.post_url, remaining_count, history.delay)
        )
        thread.daemon = True
        thread.start()
        
        # Store the task reference
        current_tasks[task_id] = thread
        
        # Log the action
        log_user_activity(
            current_user.id,
            f"Resumed sharing task {task_id} ({remaining_count} shares left)",
            request.remote_addr
        )
        
        return jsonify({
            "success": True,
            "message": f"Resumed sharing task with {remaining_count} shares left"
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/get_history')
@login_required
def get_share_history():
    """API endpoint to get user's sharing history"""
    try:
        # Get the user's share history
        history_records = ShareHistory.query.filter_by(user_id=current_user.id).order_by(ShareHistory.created_at.desc()).all()
        
        # Convert history records to dictionaries
        history_list = [record.to_dict() for record in history_records]
        
        return jsonify({
            "success": True,
            "history": history_list
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
