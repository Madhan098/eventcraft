from flask import render_template, request, jsonify, session, redirect, url_for, flash, send_from_directory, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from extensions import db
from models import User, OTP, Invitation, Template, EventType, Wish, Guest, RSVP, InvitationView, InvitationShare, PersonalMessage, Memory
from utils import send_otp_email, generate_otp
from datetime import datetime, timedelta
import json
import random
import string
import os
import requests
from urllib.parse import urlencode, quote
import threading
import time

# Simple in-memory cache for OAuth states as fallback
oauth_state_cache = {}
cache_lock = threading.Lock()

def store_oauth_state(state, timestamp):
    """Store OAuth state in memory cache as fallback"""
    with cache_lock:
        oauth_state_cache[state] = timestamp
        # Clean up old entries (older than 10 minutes)
        current_time = time.time()
        expired_keys = [k for k, v in oauth_state_cache.items() if current_time - v > 600]
        for key in expired_keys:
            del oauth_state_cache[key]

def get_oauth_state(state):
    """Get OAuth state from memory cache"""
    with cache_lock:
        return oauth_state_cache.get(state)

def remove_oauth_state(state):
    """Remove OAuth state from memory cache"""
    with cache_lock:
        oauth_state_cache.pop(state, None)

# Helper function to check authentication (moved outside register_routes)
def is_authenticated():
    return 'user_id' in session

def is_admin():
    """Check if current user is admin"""
    if not is_authenticated():
        return False
    user = User.query.get(session['user_id'])
    return user and user.is_admin

def generate_unique_share_url():
    """Generate a unique share URL for invitations - Optimized"""
    max_attempts = 10
    for attempt in range(max_attempts):
        # Generate a random 12-character string (more unique, less collisions)
        share_url = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        
        # Check if it already exists - use exists() for better performance
        exists = db.session.query(Invitation.share_url).filter_by(share_url=share_url).first() is not None
        if not exists:
            return share_url
    
    # Fallback: use timestamp + random if all attempts fail
    import time
    share_url = f"{int(time.time())}{''.join(random.choices(string.ascii_letters + string.digits, k=6))}"
    return share_url

def is_invitation_expired(invitation):
    """Check if an invitation has expired"""
    if not invitation.expires_at:
        return False
    return datetime.utcnow() > invitation.expires_at

def generate_google_calendar_url(invitation):
    """Generate Google Calendar URL for adding event"""
    try:
        # Format event details
        event_title = invitation.title or 'Event Invitation'
        event_description = invitation.description or ''
        
        # Format event date
        if invitation.event_date:
            if isinstance(invitation.event_date, str):
                event_date = invitation.event_date
            else:
                event_date = invitation.event_date.strftime('%Y%m%d')
        else:
            event_date = datetime.utcnow().strftime('%Y%m%d')
        
        # Format event location
        event_location = invitation.venue_address or ''
        
        # Create Google Calendar URL
        calendar_url = f"https://calendar.google.com/calendar/render?action=TEMPLATE"
        calendar_url += f"&text={quote(event_title)}"
        calendar_url += f"&dates={event_date}/{event_date}"
        calendar_url += f"&details={quote(event_description)}"
        calendar_url += f"&location={quote(event_location)}"
        
        return calendar_url
        
    except Exception as e:
        current_app.logger.error(f"Error generating Google Calendar URL: {str(e)}")
        return None

def register_routes(app):
    # Custom Jinja2 filter for safe JSON parsing
    @app.template_filter('safe_from_json')
    def safe_from_json(value):
        try:
            if value and value.strip() and value != 'null':
                parsed = json.loads(value)
                # Ensure it's a list and filter out empty strings
                if isinstance(parsed, list):
                    return [item for item in parsed if item and str(item).strip()]
                return []
            return []
        except (json.JSONDecodeError, AttributeError, TypeError):
            return []

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('errors/500.html'), 500

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/error.html', 
                             error_code=403,
                             error_title='Access Forbidden',
                             error_message="You don't have permission to access this resource. Please check your credentials and try again."), 403

    @app.errorhandler(400)
    def bad_request_error(error):
        return render_template('errors/error.html',
                             error_code=400,
                             error_title='Bad Request',
                             error_message="The request was invalid. Please check your input and try again."), 400

    # Export routes
    @app.route('/api/invitations/<int:invitation_id>/export/<format>')
    def export_guest_list(invitation_id, format):
        """Export guest list in various formats"""
        if not is_authenticated():
            return jsonify({'error': 'Authentication required'}), 401
        
        invitation = Invitation.query.get_or_404(invitation_id)
        
        # Check if user owns this invitation
        if invitation.user_id != session.get('user_id'):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get all guests and their RSVP data
        guests = Guest.query.filter_by(invitation_id=invitation_id).all()
        
        if format == 'csv':
            return export_csv(guests, invitation)
        elif format == 'excel':
            return export_excel(guests, invitation)
        elif format == 'pdf':
            return export_pdf(guests, invitation)
        else:
            return jsonify({'error': 'Invalid format'}), 400

    @app.route('/')
    def index():
        if is_authenticated():
            return redirect(url_for('dashboard'))
        return render_template('index.html')

    @app.route('/images/<path:filename>')
    def serve_image(filename):
        """Serve images from the root images folder and subdirectories"""
        try:
            import os
            from pathlib import Path
            
            # Handle subdirectories like templatesimages/filename.png
            if '/' in filename:
                # Build the full path
                image_path = os.path.join('images', filename)
                # Check if file exists
                if os.path.exists(image_path) and os.path.isfile(image_path):
                    # Extract directory and filename
                    parts = filename.split('/')
                    directory = '/'.join(parts[:-1])
                    file = parts[-1]
                    full_path = os.path.join('images', directory)
                    return send_from_directory(full_path, file)
                else:
                    app.logger.warning(f"Image not found: {image_path}")
                    return "Image not found", 404
            else:
                # Direct file in images folder
                image_path = os.path.join('images', filename)
                if os.path.exists(image_path) and os.path.isfile(image_path):
                    return send_from_directory('images', filename)
                else:
                    app.logger.warning(f"Image not found: {image_path}")
                    return "Image not found", 404
        except Exception as e:
            app.logger.error(f"Error serving image {filename}: {str(e)}")
            import traceback
            traceback.print_exc()
            return "Image not found", 404

    @app.route('/auth')
    def auth():
        if is_authenticated():
            return redirect(url_for('dashboard'))
        return render_template('auth/login.html')

    @app.route('/register', methods=['POST'])
    def register():
        try:
            data = request.form
            
            # Check if user already exists
            if User.query.filter_by(email=data['email']).first():
                flash('Email already registered', 'error')
                return redirect(url_for('auth'))
            
            if User.query.filter_by(mobile=data['mobile']).first():
                flash('Mobile number already registered', 'error')
                return redirect(url_for('auth'))
            
            # Invalidate any existing unused OTPs for this email (if resending)
            existing_otps = OTP.query.filter_by(
                email=data['email'],
                purpose='verification',
                is_used=False
            ).all()
            
            for existing_otp in existing_otps:
                existing_otp.is_used = True
            
            # Create new user
            user = User(
                name=data['name'],
                mobile=data['mobile'],
                email=data['email'],
                password_hash=generate_password_hash(data['password'])
            )
            db.session.add(user)
            db.session.commit()
            
            # Generate and send OTP
            otp_code = generate_otp()
            otp = OTP(
                email=data['email'],
                otp_code=otp_code,
                purpose='verification',
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp)
            db.session.commit()
            
            # Send OTP email - check if email was sent successfully
            email_sent = send_otp_email(data['email'], otp_code, purpose='verification')
            
            if not email_sent:
                # If email failed, still allow user to proceed but warn them
                app.logger.warning(f"OTP email failed to send to {data['email']}, but OTP was generated: {otp_code}")
                flash('OTP sent to your email. Please check your inbox. If you don\'t see it, check spam folder.', 'warning')
            else:
                flash('OTP sent to your email. Please check your inbox.', 'success')
            
            session['temp_email'] = data['email']
            
            return redirect(url_for('verify_otp'))
            
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            return redirect(url_for('auth'))

    @app.route('/login', methods=['POST'])
    def login():
        try:
            data = request.form
            
            user = User.query.filter_by(email=data['email']).first()
            
            if user and check_password_hash(user.password_hash, data['password']):
                if not user.is_verified:
                    flash('Please verify your email first', 'error')
                    return redirect(url_for('auth'))
                
                session['user_id'] = user.id
                session['user_name'] = user.name
                session['user_email'] = user.email
                session.permanent = True
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
                return redirect(url_for('auth'))
                
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('Login failed', 'error')
            return redirect(url_for('auth'))

    @app.route('/verify-otp')
    def verify_otp():
        if 'temp_email' not in session:
            return redirect(url_for('auth'))
        return render_template('auth/verify_otp.html', email=session['temp_email'])

    @app.route('/verify-otp', methods=['POST'])
    def verify_otp_post():
        try:
            otp_code = request.form.get('otp', '').strip()
            email = session.get('temp_email')
            
            if not email:
                flash('Session expired. Please register again.', 'error')
                return redirect(url_for('auth'))
            
            if not otp_code or len(otp_code) != 6:
                flash('Please enter a valid 6-digit OTP', 'error')
                return redirect(url_for('verify_otp'))
            
            # Find the OTP
            otp = OTP.query.filter_by(
                email=email, 
                otp_code=otp_code, 
                is_used=False,
                purpose='verification'
            ).first()
            
            if not otp:
                flash('Invalid OTP. Please check and try again.', 'error')
                return redirect(url_for('verify_otp'))
            
            if otp.expires_at < datetime.utcnow():
                flash('OTP has expired. Please register again to get a new OTP.', 'error')
                # Mark as used so it can't be reused
                otp.is_used = True
                db.session.commit()
                return redirect(url_for('auth'))
            
            # Mark OTP as used
            otp.is_used = True
            
            # Verify the user
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_verified = True
                db.session.commit()
                
                # Automatically log in the user
                session['user_id'] = user.id
                session['user_name'] = user.name
                session['user_email'] = user.email
                session.permanent = True
                
                # Clear temp session
                session.pop('temp_email', None)
                
                flash('Email verified successfully! Welcome to EventCraft!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('User not found', 'error')
                return redirect(url_for('auth'))
                
        except Exception as e:
            app.logger.error(f"OTP verification error: {str(e)}")
            db.session.rollback()
            flash('Verification failed. Please try again.', 'error')
            return redirect(url_for('verify_otp'))

    @app.route('/oauth-debug')
    def oauth_debug():
        """Debug OAuth configuration"""
        debug_info = {
            'client_id': app.config.get('GOOGLE_CLIENT_ID', 'Not set'),
            'client_secret': 'Set' if app.config.get('GOOGLE_CLIENT_SECRET') else 'Not set',
            'redirect_uri': app.config.get('GOOGLE_REDIRECT_URI', 'Not set'),
            'session_state': session.get('oauth_state', 'Not set'),
            'is_render': bool(os.environ.get('RENDER')),
            'environment': 'Production' if os.environ.get('RENDER') else 'Development'
        }
        return f"<pre>{debug_info}</pre>"

    @app.route('/debug/oauth')
    def debug_oauth():
        """Debug OAuth configuration"""
        if not app.config.get('GOOGLE_CLIENT_ID'):
            return jsonify({
                'error': 'GOOGLE_CLIENT_ID not configured',
                'redirect_uri': app.config.get('GOOGLE_REDIRECT_URI'),
                'session_secret_set': bool(app.secret_key)
            })
        
        return jsonify({
            'client_id': app.config['GOOGLE_CLIENT_ID'][:10] + '...',
            'redirect_uri': app.config['GOOGLE_REDIRECT_URI'],
            'session_secret_set': bool(app.secret_key),
            'session_id': session.get('_id', 'No session ID'),
            'session_keys': list(session.keys())
        })

    @app.route('/auth/google')
    def google_auth():
        """Initiate Google OAuth flow"""
        if is_authenticated():
            return redirect(url_for('dashboard'))
        
        # Check if Google OAuth is configured
        if not app.config.get('GOOGLE_CLIENT_ID') or not app.config.get('GOOGLE_CLIENT_SECRET'):
            app.logger.error("Google OAuth not configured - missing CLIENT_ID or CLIENT_SECRET")
            flash('Google OAuth is not configured. Please contact support or check your environment variables.', 'error')
            return redirect(url_for('auth'))
        
        # Generate state parameter for security
        state = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        
        # Store state in session with additional security
        session['oauth_state'] = state
        session['oauth_timestamp'] = datetime.utcnow().timestamp()
        session.permanent = True  # Make session persistent
        
        # Also store in memory cache as fallback
        store_oauth_state(state, time.time())
        
        # Force session to be saved
        session.modified = True
        
        # Debug logging
        app.logger.info(f"Generated OAuth state: {state}")
        app.logger.info(f"Session ID: {session.get('_id', 'No session ID')}")
        app.logger.info(f"Redirect URI: {app.config['GOOGLE_REDIRECT_URI']}")
        app.logger.info(f"Client ID: {app.config['GOOGLE_CLIENT_ID']}")
        
        # Google OAuth URL
        params = {
            'client_id': app.config['GOOGLE_CLIENT_ID'],
            'redirect_uri': app.config['GOOGLE_REDIRECT_URI'],
            'scope': 'openid email profile',
            'response_type': 'code',
            'state': state,
            'access_type': 'offline',
            'prompt': 'consent'
        }
        
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
        app.logger.info(f"OAuth URL: {auth_url}")
        return redirect(auth_url)

    @app.route('/auth/google/callback')
    def google_callback():
        """Handle Google OAuth callback"""
        try:
            # Check for OAuth errors
            error = request.args.get('error')
            if error:
                error_description = request.args.get('error_description', 'Unknown error')
                app.logger.error(f"Google OAuth error: {error} - {error_description}")
                flash(f'Google authentication failed: {error_description}', 'error')
                return redirect(url_for('auth'))
            
            # Verify state parameter
            received_state = request.args.get('state')
            stored_state = session.get('oauth_state')
            stored_timestamp = session.get('oauth_timestamp')
            
            # Debug logging
            app.logger.info(f"OAuth callback - Received state: {received_state}")
            app.logger.info(f"OAuth callback - Stored state: {stored_state}")
            app.logger.info(f"OAuth callback - Session ID: {session.get('_id', 'No session ID')}")
            app.logger.info(f"OAuth callback - Session keys: {list(session.keys())}")
            
            # Check if state exists and matches
            if not received_state:
                app.logger.error("No state parameter received from Google")
                flash('Missing state parameter. Please try again.', 'error')
                return redirect(url_for('auth'))
            
            # Try session first, then fallback to cache
            state_valid = False
            if stored_state and received_state == stored_state:
                # Check timestamp (state should be valid for 10 minutes)
                if stored_timestamp:
                    current_time = datetime.utcnow().timestamp()
                    if current_time - stored_timestamp <= 600:  # 10 minutes
                        state_valid = True
                        app.logger.info("State validated from session")
                else:
                    state_valid = True
            else:
                # Try fallback cache
                cache_timestamp = get_oauth_state(received_state)
                if cache_timestamp:
                    current_time = time.time()
                    if current_time - cache_timestamp <= 600:  # 10 minutes
                        state_valid = True
                        app.logger.info("State validated from cache fallback")
                        # Clear from cache
                        remove_oauth_state(received_state)
            
            if not state_valid:
                app.logger.error(f"State validation failed: received={received_state}, stored={stored_state}")
                flash('Invalid or expired state parameter. Please try again.', 'error')
                return redirect(url_for('auth'))
            
            # Clear the state parameter after successful verification
            session.pop('oauth_state', None)
            session.pop('oauth_timestamp', None)
            
            code = request.args.get('code')
            if not code:
                flash('Authorization code not received', 'error')
                return redirect(url_for('auth'))
            
            # Exchange code for tokens
            token_url = 'https://oauth2.googleapis.com/token'
            token_data = {
                'client_id': app.config['GOOGLE_CLIENT_ID'],
                'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': app.config['GOOGLE_REDIRECT_URI']
            }
            
            token_response = requests.post(token_url, data=token_data)
            
            if token_response.status_code != 200:
                app.logger.error(f"Token exchange failed: {token_response.status_code} - {token_response.text}")
                flash('Failed to exchange authorization code for token', 'error')
                return redirect(url_for('auth'))
            
            token_json = token_response.json()
            
            if 'access_token' not in token_json:
                app.logger.error(f"Token response missing access_token: {token_json}")
                flash('Failed to get access token from Google', 'error')
                return redirect(url_for('auth'))
            
            # Get user info from Google
            user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
            headers = {'Authorization': f"Bearer {token_json['access_token']}"}
            user_response = requests.get(user_info_url, headers=headers)
            user_info = user_response.json()
            
            if 'email' not in user_info:
                flash('Failed to get user information', 'error')
                return redirect(url_for('auth'))
            
            # Check if user exists
            user = User.query.filter_by(email=user_info['email']).first()
            
            if not user:
                # Create new user
                user = User(
                    name=user_info.get('name', ''),
                    email=user_info['email'],
                    mobile='',  # Google doesn't provide mobile
                    password_hash='',  # No password for OAuth users
                    is_verified=True,  # Google users are pre-verified
                    google_id=user_info.get('id', '')
                )
                db.session.add(user)
                db.session.commit()
                flash('Account created successfully! Welcome to EventCraft!', 'success')
            else:
                # Update existing user with Google ID if not set
                if not user.google_id:
                    user.google_id = user_info.get('id', '')
                    user.is_verified = True
                    db.session.commit()
                flash('Welcome back!', 'success')
            
            # Log in the user
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
            session.permanent = True
            
            # Clear OAuth state
            session.pop('oauth_state', None)
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            app.logger.error(f"Google OAuth error: {str(e)}")
            flash('Google authentication failed. Please try again.', 'error')
            return redirect(url_for('auth'))

    @app.route('/dashboard')
    def dashboard():
        if not is_authenticated():
            flash('Please login to continue', 'error')
            return redirect(url_for('auth'))
        
        # Check if user is admin and redirect to admin dashboard
        if is_admin():
            return redirect(url_for('admin_dashboard'))
        
        user_id = session['user_id']
        user_name = session.get('user_name', 'User')
        user_email = session.get('user_email', '')
        
        # Create user object for template
        user = {
            'id': user_id,
            'name': user_name,
            'email': user_email
        }
        
        try:
            # Try to query invitations with error handling for missing columns
            invitations = Invitation.query.filter_by(user_id=user_id).order_by(Invitation.created_at.desc()).all()
        except Exception as e:
            app.logger.error(f"Dashboard error: {str(e)}")
            # If there's a database schema issue, show empty invitations list
            invitations = []
            flash('Database schema needs updating. Please contact administrator.', 'warning')
        
        # Calculate stats
        total_guests = sum(len(invitation.guests) for invitation in invitations)
        total_rsvps = sum(len([guest for guest in invitation.guests if guest.rsvp_status]) for invitation in invitations)
        
        return render_template('dashboard/dashboard.html', 
                             invitations=invitations, 
                             user=user,
                             total_guests=total_guests,
                             total_rsvps=total_rsvps)

    @app.route('/logout')
    def logout():
        session.clear()
        flash('Logged out successfully', 'success')
        return redirect(url_for('index'))

    # Admin Routes
    @app.route('/admin')
    def admin_dashboard():
        """Admin dashboard for user management"""
        if not is_admin():
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get all users
        users = User.query.order_by(User.created_at.desc()).all()
        
        # Get all invitations
        invitations = Invitation.query.order_by(Invitation.created_at.desc()).all()
        
        # Calculate statistics
        total_users = len(users)
        verified_users = len([u for u in users if u.is_verified])
        admin_users = len([u for u in users if u.is_admin])
        total_invitations = len(invitations)
        total_views = sum(invitation.view_count for invitation in invitations)
        
        # Get recent activity
        recent_users = users[:5]  # Last 5 registered users
        recent_invitations = invitations[:5]  # Last 5 created invitations
        
        stats = {
            'total_users': total_users,
            'verified_users': verified_users,
            'admin_users': admin_users,
            'total_invitations': total_invitations,
            'total_views': total_views
        }
        
        return render_template('admin/dashboard.html', 
                             users=users,
                             invitations=invitations,
                             stats=stats,
                             recent_users=recent_users,
                             recent_invitations=recent_invitations)

    @app.route('/admin/users')
    def admin_users():
        """Admin user management page"""
        if not is_admin():
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template('admin/users.html', users=users)

    @app.route('/admin/invitations')
    def admin_invitations():
        """Admin invitation management page"""
        if not is_admin():
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        
        invitations = Invitation.query.order_by(Invitation.created_at.desc()).all()
        return render_template('admin/invitations.html', invitations=invitations)

    @app.route('/admin/user/<int:user_id>/toggle-status', methods=['POST'])
    def toggle_user_status(user_id):
        """Toggle user verification status"""
        if not is_admin():
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        try:
            user = User.query.get_or_404(user_id)
            user.is_verified = not user.is_verified
            db.session.commit()
            
            status = 'verified' if user.is_verified else 'unverified'
            return jsonify({
                'success': True, 
                'message': f'User {status} successfully',
                'is_verified': user.is_verified
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to update user status'}), 500

    @app.route('/admin/user/<int:user_id>/delete', methods=['DELETE'])
    def delete_user(user_id):
        """Delete a user (admin only)"""
        if not is_admin():
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        try:
            user = User.query.get_or_404(user_id)
            
            # Don't allow deleting admin users
            if user.is_admin:
                return jsonify({'success': False, 'message': 'Cannot delete admin users'}), 400
            
            # Delete user (cascade will handle invitations)
            db.session.delete(user)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to delete user'}), 500

    @app.route('/templates')
    def templates():
        # Templates page is public - no login required
        # Optimize: Only fetch active event types
        event_types = EventType.query.filter_by(is_active=True).order_by(EventType.sort_order.asc()).all()
        
        # Fetch all active templates - Only templates with images from templatesimages/
        templates = Template.query.filter_by(is_active=True)\
            .filter(Template.preview_image.like('/images/templatesimages/%'))\
            .order_by(Template.created_at.desc()).all()
        
        return render_template('templates.html', event_types=event_types, templates=templates)

    @app.route('/admin/sync-template-images', methods=['POST'])
    def sync_template_images():
        """Sync templates from images/templatesimages folder to database"""
        if not is_admin():
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        try:
            from pathlib import Path
            
            templates_folder = Path('images/templatesimages')
            
            if not templates_folder.exists():
                return jsonify({
                    'success': False,
                    'message': f'Folder {templates_folder} does not exist!'
                }), 400
            
            template_images = list(templates_folder.glob('*.png')) + list(templates_folder.glob('*.jpg')) + list(templates_folder.glob('*.jpeg'))
            
            imported_count = 0
            updated_count = 0
            
            # Ensure wedding event type exists
            wedding_type = EventType.query.filter_by(name='wedding').first()
            if not wedding_type:
                wedding_type = EventType(
                    name='wedding',
                    display_name='Wedding',
                    description='Celebrate the union of two hearts',
                    icon='fas fa-heart',
                    color='#e91e63',
                    sort_order=1,
                    is_active=True
                )
                db.session.add(wedding_type)
                db.session.commit()
            
            for img_path in template_images:
                # Extract template name from filename
                filename = img_path.stem
                filename_lower = filename.lower()
                
                # Determine event type from filename
                # Check for specific patterns first (e.g., "wedding anniversary" should be anniversary)
                event_type = 'birthday'  # Default
                if 'anniversary' in filename_lower:
                    event_type = 'anniversary'
                elif 'wedding' in filename_lower:
                    event_type = 'wedding'
                elif 'birthday' in filename_lower:
                    event_type = 'birthday'
                elif 'babyshower' in filename_lower or 'baby' in filename_lower:
                    event_type = 'babyshower'
                elif 'graduation' in filename_lower or 'grduation' in filename_lower:
                    event_type = 'graduation'
                elif 'retirement' in filename_lower:
                    event_type = 'retirement'
                
                # Generate template name from filename
                template_name = filename
                
                # Clean up the name - remove common suffixes
                template_name = template_name.replace(' Mobile Video', '').replace(' Mobile', '').strip()
                template_name = template_name.replace('_', ' ').replace('-', ' ')
                
                # Capitalize properly
                words = template_name.split()
                template_name = ' '.join(word.capitalize() for word in words)
                
                # Handle specific patterns
                if 'cream and pink wedding anniversary' in filename_lower:
                    template_name = 'Cream and Pink Wedding Anniversary'
                elif 'ballonbirthday' in filename_lower or 'ballon birthday' in filename_lower:
                    template_name = 'Balloon Birthday'
                elif 'birthdayblackgold' in filename_lower or 'birthday black gold' in filename_lower:
                    template_name = 'Black Gold Birthday'
                elif 'birthdaycolourful' in filename_lower or 'birthday colourful' in filename_lower:
                    template_name = 'Colorful Birthday'
                elif 'cream and pink floral wedding' in filename_lower:
                    template_name = 'Cream and Pink Floral Wedding'
                elif 'pastel romantic wedding' in filename_lower:
                    template_name = 'Pastel Romantic Wedding'
                elif filename_lower == 'wedding':
                    template_name = 'Elegant Wedding'
                
                if not template_name:
                    template_name = filename.replace('_', ' ').title()
                
                # Image path relative to images folder
                image_path = f'/images/templatesimages/{img_path.name}'
                
                # Check if template exists (by name and event type to avoid duplicates)
                existing_template = Template.query.filter_by(name=template_name, event_type=event_type).first()
                
                if existing_template:
                    # Update existing template
                    existing_template.preview_image = image_path
                    existing_template.is_active = True
                    updated_count += 1
                else:
                    # Create new template
                    new_template = Template(
                        name=template_name,
                        description=f'Elegant {template_name} invitation template',
                        event_type=event_type,
                        religious_type='general',
                        style='modern',
                        color_scheme='A07878',
                        preview_image=image_path,
                        is_active=True
                    )
                    db.session.add(new_template)
                    imported_count += 1
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Successfully synced templates from folder',
                'imported': imported_count,
                'updated': updated_count,
                'total': imported_count + updated_count
            })
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error syncing template images: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'success': False,
                'message': f'Error syncing templates: {str(e)}'
            }), 500

    @app.route('/admin/import-templates', methods=['POST'])
    def import_templates():
        """Import templates from external Momento site"""
        if not is_admin():
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        try:
            # Fetch templates from Momento site
            external_url = 'https://momento-33ed8a78.base44.app/createinvite'
            
            # Try to get templates - this might require API endpoint or scraping
            # For now, we'll create a manual import function
            # You may need to inspect the site's API or HTML structure
            
            response = requests.get(external_url, timeout=10)
            if response.status_code != 200:
                return jsonify({
                    'success': False, 
                    'message': f'Failed to fetch from external site: {response.status_code}'
                }), 400
            
            # Parse the response - this depends on the actual structure of the site
            # You may need to adjust based on how templates are returned
            # For now, we'll provide a structure that can be extended
            
            imported_count = 0
            
            # Example: If the site returns JSON templates
            try:
                data = response.json()
                templates_data = data.get('templates', [])
                
                for template_data in templates_data:
                    # Extract template information
                    name = template_data.get('name', f'Template {len(Template.query.all()) + 1}')
                    event_type = template_data.get('event_type', 'birthday')
                    preview_image = template_data.get('preview_image', '')
                    description = template_data.get('description', '')
                    style = template_data.get('style', 'modern')
                    color_scheme = template_data.get('color_scheme', '')
                    
                    # Check if template already exists
                    existing = Template.query.filter_by(name=name, event_type=event_type).first()
                    if not existing:
                        new_template = Template(
                            name=name,
                            description=description,
                            event_type=event_type,
                            religious_type='general',
                            style=style,
                            color_scheme=color_scheme,
                            preview_image=preview_image,
                            is_active=True
                        )
                        db.session.add(new_template)
                        imported_count += 1
                        
            except (ValueError, KeyError) as e:
                # If not JSON, try parsing HTML
                from bs4 import BeautifulSoup
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # Extract template data from HTML - adjust selectors based on actual structure
                    template_cards = soup.find_all('div', class_='template-card') or soup.find_all('div', {'data-template': True})
                    
                    for card in template_cards:
                        name = card.get('data-name') or card.find('h3') or 'Unknown Template'
                        if isinstance(name, type(soup)):
                            name = name.text.strip() if hasattr(name, 'text') else str(name)
                        
                        # Try to extract image
                        img = card.find('img')
                        preview_image = img.get('src', '') if img else ''
                        
                        # Create template if it doesn't exist
                        existing = Template.query.filter_by(name=name).first()
                        if not existing:
                            new_template = Template(
                                name=name,
                                description=f'Imported from Momento',
                                event_type='birthday',  # Default, can be updated
                                religious_type='general',
                                style='modern',
                                preview_image=preview_image,
                                is_active=True
                            )
                            db.session.add(new_template)
                            imported_count += 1
                            
                except Exception as html_error:
                    # If parsing fails, provide manual import option
                    return jsonify({
                        'success': False,
                        'message': f'Could not parse templates. You may need to add them manually. Error: {str(html_error)}',
                        'suggestion': 'Visit the site and manually add templates through the admin panel'
                    }), 400
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Successfully imported {imported_count} templates',
                'count': imported_count
            })
            
        except requests.RequestException as e:
            return jsonify({
                'success': False,
                'message': f'Failed to connect to external site: {str(e)}'
            }), 500
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error importing templates: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Error importing templates: {str(e)}'
            }), 500

    @app.route('/preview-template/<template_name>')
    def preview_template(template_name):
        """Preview a template without creating an invitation"""
        try:
            # Get event type from URL parameter if provided, otherwise determine from template name
            event_type = request.args.get('event_type')
            
            if not event_type:
                # Determine event type from template name
                if 'birthday' in template_name:
                    event_type = 'birthday'
                elif 'anniversary' in template_name:
                    event_type = 'anniversary'
                elif 'babyshower' in template_name:
                    event_type = 'babyshower'
                elif 'graduation' in template_name:
                    event_type = 'graduation'
                elif 'retirement' in template_name:
                    event_type = 'retirement'
                elif 'wedding' in template_name:
                    event_type = 'wedding'
                elif 'hindu' in template_name:
                    event_type = 'naming'
                else:
                    event_type = 'wedding'  # default
            
            # Create template-specific sample data based on the actual template name
            sample_event_data = get_template_sample_data(template_name, event_type)
            
            # Sample invitation object for templates that expect it
            sample_invitation = {
                'id': 'preview',
                'title': sample_event_data.get('eventTitle', 'Sample Event Invitation'),
                'event_type': event_type,
                'venue_address': sample_event_data.get('venueAddress', '123 Main Street, City, State 12345'),
                'customization_data': '{"language": "en", "font_style": "elegant"}',
                'created_at': '2024-01-01',
                'is_active': True
            }
            
            # Render the template with both event_data and invitation
            template_path = f'invitation/templates/{template_name}.html'
            return render_template(template_path, event_data=sample_event_data, invitation=sample_invitation)
            
        except Exception as e:
            app.logger.error(f"Error previewing template {template_name}: {str(e)}")
            return f"Error loading template preview: {str(e)}", 404

    def get_template_sample_data(template_name, event_type):
        """Generate consistent sample data for each template"""
        base_data = {
            'shareUrl': 'preview',
            'timeData': {
                'startTime': '7:00 PM',
                'dinnerTime': '8:00 PM'
            },
            'venueData': {
                'venue': 'Grand Ballroom',
                'address': '123 Main Street, City, State 12345'
            },
            'venueAddress': '123 Main Street, City, State 12345',
            'contactPhone': '+1 (555) 123-4567',
            'contactEmail': 'john.doe@example.com',
            'mainImage': None,
            'birthdayImage': None,
            'galleryImages': []
        }
        
        # Provide consistent sample data based on the actual template name
        # This ensures each template shows its own specific preview content
        if 'birthday_fun_colorful' in template_name:
            # This template is used for multiple event types, provide event-specific content
            if event_type == 'festival':
                return {
                    **base_data,
                    'eventTitle': 'Diwali Festival Celebration',
                    'event_type': 'festival',
                    'title': 'Festival Celebration',
                    'date': '2024-12-25',
                    'time': '6:00 PM',
                    'location': '123 Main Street, City',
                    'description': 'Join us in celebrating the festival of lights!',
                    'host_name': 'Community Center',
                    'hostName': 'Community Center',
                    'festivalName': 'Diwali',
                    'celebrationType': 'Community Festival'
                }
            elif event_type == 'party':
                return {
                    **base_data,
                    'eventTitle': 'Fun Party Night',
                    'event_type': 'party',
                    'title': 'Party Celebration',
                    'date': '2024-12-25',
                    'time': '8:00 PM',
                    'location': '123 Main Street, City',
                    'description': 'Join us for an amazing party night!',
                    'host_name': 'Sarah',
                    'hostName': 'Sarah',
                    'partyType': 'Fun Party',
                    'theme': 'Dance & Music'
                }
            else:  # default to birthday
                return {
                    **base_data,
                    'eventTitle': 'Sarah\'s 25th Birthday Celebration',
                    'event_type': 'birthday',
                    'title': 'Birthday Party',
                    'date': '2024-12-25',
                    'time': '7:00 PM',
                    'location': '123 Main Street, City',
                    'description': 'Join us for a fun birthday celebration!',
                    'host_name': 'Sarah\'s Family',
                    'hostName': 'Sarah\'s Family',
                    'birthdayPerson': 'Sarah Johnson',
                    'age': '25',
                    'birthdayDescription': 'Celebrating another year of amazing memories'
                }
        elif 'birthday_elegant' in template_name:
            return {
                **base_data,
                'eventTitle': 'Elegant Birthday Celebration',
                'event_type': 'birthday',
                'title': 'Birthday Celebration',
                'date': '2024-12-25',
                'time': '7:00 PM',
                'location': '123 Main Street, City',
                'description': 'Join us for an elegant birthday celebration!',
                'host_name': 'Sarah\'s Family',
                'hostName': 'Sarah\'s Family',
                'birthdayPerson': 'Sarah Johnson',
                'age': '25',
                'birthdayDescription': 'Celebrating another year of elegance and grace'
            }
        elif 'birthday_final_elegant' in template_name:
            return {
                **base_data,
                'eventTitle': 'Final Elegant Birthday',
                'event_type': 'birthday',
                'title': 'Birthday Celebration',
                'date': '2024-12-25',
                'time': '7:00 PM',
                'location': '123 Main Street, City',
                'description': 'Join us for the most elegant birthday celebration!',
                'host_name': 'Sarah\'s Family',
                'hostName': 'Sarah\'s Family',
                'birthdayPerson': 'Sarah Johnson',
                'age': '25',
                'birthdayDescription': 'The ultimate elegant birthday celebration'
            }
        elif 'anniversary_golden_elegant' in template_name:
            return {
                **base_data,
                'eventTitle': 'John & Sarah\'s 10th Anniversary',
                'event_type': 'anniversary',
                'title': 'Anniversary Celebration',
                'date': '2024-12-25',
                'time': '7:00 PM',
                'location': '123 Main Street, City',
                'description': 'Join us in celebrating 10 years of love and happiness!',
                'host_name': 'John & Sarah',
                'hostName': 'John & Sarah',
                'anniversaryYears': '10',
                'coupleNames': 'John & Sarah'
            }
        elif 'babyshower_sweet_pink' in template_name:
            return {
                **base_data,
                'eventTitle': 'Baby Shower for Sarah',
                'event_type': 'babyshower',
                'title': 'Baby Shower',
                'date': '2024-12-25',
                'time': '2:00 PM',
                'location': '123 Main Street, City',
                'description': 'Join us in celebrating the upcoming arrival of baby!',
                'host_name': 'Sarah\'s Friends',
                'hostName': 'Sarah\'s Friends',
                'momToBe': 'Sarah',
                'babyGender': 'Surprise',
                'dueDate': 'March 2025'
            }
        elif 'graduation_success_modern' in template_name:
            return {
                **base_data,
                'eventTitle': 'Sarah\'s Graduation Celebration',
                'event_type': 'graduation',
                'title': 'Graduation Party',
                'date': '2024-12-25',
                'time': '6:00 PM',
                'location': '123 Main Street, City',
                'description': 'Join us in celebrating Sarah\'s academic achievement!',
                'host_name': 'Sarah\'s Family',
                'hostName': 'Sarah\'s Family',
                'graduateName': 'Sarah Johnson',
                'degree': 'Bachelor of Science',
                'university': 'University of Success'
            }
        elif 'retirement_golden_classic' in template_name:
            return {
                **base_data,
                'eventTitle': 'John\'s Retirement Celebration',
                'event_type': 'retirement',
                'title': 'Retirement Party',
                'date': '2024-12-25',
                'time': '6:00 PM',
                'location': '123 Main Street, City',
                'description': 'Join us in celebrating John\'s 30 years of dedicated service!',
                'host_name': 'John\'s Colleagues',
                'hostName': 'John\'s Colleagues',
                'retireeName': 'John Smith',
                'yearsOfService': '30',
                'company': 'ABC Corporation'
            }
        elif 'wedding_elegant_modern' in template_name:
            # This template is used for multiple event types, provide event-specific content
            if event_type == 'housewarming':
                return {
                    **base_data,
                    'eventTitle': 'New Home Celebration',
                    'event_type': 'housewarming',
                    'title': 'House Warming Party',
                    'date': '2024-12-25',
                    'time': '6:00 PM',
                    'location': '123 New Home Street, City',
                    'description': 'Join us in celebrating our new home!',
                    'host_name': 'John & Sarah',
                    'hostName': 'John & Sarah',
                    'homeowners': 'John & Sarah',
                    'newAddress': '123 New Home Street, City'
                }
            elif event_type == 'corporate':
                return {
                    **base_data,
                    'eventTitle': 'Annual Corporate Gala 2024',
                    'event_type': 'corporate',
                    'title': 'Corporate Event',
                    'date': '2024-12-25',
                    'time': '7:00 PM',
                    'location': 'Grand Convention Center, City',
                    'description': 'Join us for our annual corporate celebration and networking event.',
                    'host_name': 'ABC Corporation',
                    'hostName': 'ABC Corporation',
                    'companyName': 'ABC Corporation',
                    'eventType': 'Annual Gala',
                    'dressCode': 'Business Formal'
                }
            else:  # default to wedding
                return {
                    **base_data,
                    'eventTitle': 'John & Sarah\'s Modern Wedding',
                    'event_type': 'wedding',
                    'title': 'Wedding Celebration',
                    'date': '2024-12-25',
                    'time': '4:00 PM',
                    'location': '123 Main Street, City',
                    'description': 'Join us in celebrating our special day!',
                    'host_name': 'John & Sarah',
                    'hostName': 'John & Sarah',
                    'brideName': 'Sarah',
                    'groomName': 'John',
                    'weddingDate': 'December 25, 2024'
                }
        elif 'wedding_elegant' in template_name:
            # This template is used for multiple event types, provide event-specific content
            if event_type == 'gettogether':
                return {
                    **base_data,
                    'eventTitle': 'Family Get Together',
                    'event_type': 'gettogether',
                    'title': 'Get Together',
                    'date': '2024-12-25',
                    'time': '5:00 PM',
                    'location': '123 Main Street, City',
                    'description': 'Join us for a fun family gathering!',
                    'host_name': 'The Johnson Family',
                    'hostName': 'The Johnson Family',
                    'familyName': 'Johnson Family',
                    'gatheringType': 'Family Reunion'
                }
            else:  # default to wedding
                return {
                    **base_data,
                    'eventTitle': 'John & Sarah\'s Elegant Wedding',
                    'event_type': 'wedding',
                    'title': 'Wedding Celebration',
                    'date': '2024-12-25',
                    'time': '4:00 PM',
                    'location': '123 Main Street, City',
                    'description': 'Join us in celebrating our special day!',
                    'host_name': 'John & Sarah',
                    'hostName': 'John & Sarah',
                    'brideName': 'Sarah',
                    'groomName': 'John',
                    'weddingDate': 'December 25, 2024'
                }
        elif 'wedding_hindu_traditional' in template_name:
            # This template is used for multiple event types, provide event-specific content
            if event_type == 'naming':
                return {
                    **base_data,
                    'eventTitle': 'Baby Naming Ceremony',
                    'event_type': 'naming',
                    'title': 'Naming Ceremony',
                    'date': '2024-12-25',
                    'time': '11:00 AM',
                    'location': '123 Main Street, City',
                    'description': 'Join us in celebrating the naming of our little one!',
                    'host_name': 'John & Sarah',
                    'hostName': 'John & Sarah',
                    'babyName': 'Aarav',
                    'parents': 'John & Sarah',
                    'ceremonyType': 'Traditional Naming Ceremony'
                }
            else:  # default to wedding
                return {
                    **base_data,
                    'eventTitle': 'Traditional Hindu Wedding',
                    'event_type': 'wedding',
                    'title': 'Wedding Celebration',
                    'date': '2024-12-25',
                    'time': '4:00 PM',
                    'location': '123 Main Street, City',
                    'description': 'Join us in celebrating our traditional wedding!',
                    'host_name': 'John & Sarah',
                    'hostName': 'John & Sarah',
                    'brideName': 'Sarah',
                    'groomName': 'John',
                    'weddingDate': 'December 25, 2024'
                }
        elif 'wedding_muslim_elegant' in template_name:
            return {
                **base_data,
                'eventTitle': 'Elegant Muslim Wedding',
                'event_type': 'wedding',
                'title': 'Wedding Celebration',
                'date': '2024-12-25',
                'time': '4:00 PM',
                'location': '123 Main Street, City',
                'description': 'Join us in celebrating our elegant wedding!',
                'host_name': 'John & Sarah',
                'hostName': 'John & Sarah',
                'brideName': 'Sarah',
                'groomName': 'John',
                'weddingDate': 'December 25, 2024'
            }
        else:  # default fallback
            return {
                **base_data,
                'eventTitle': 'Sample Event Celebration',
                'event_type': event_type,
                'title': 'Event Celebration',
                'date': '2024-12-25',
                'time': '7:00 PM',
                'location': '123 Main Street, City',
                'description': 'Join us for a wonderful celebration!',
                'host_name': 'Event Host',
                'hostName': 'Event Host'
            }

    @app.route('/preview-modal/<template_name>')
    def preview_modal(template_name):
        """Show preview modal for a template"""
        return render_template('invitation/preview_modal.html', template_name=template_name)


    @app.route('/create-invitation')
    def create_invitation():
        # Improved authentication check - less aggressive, don't clear session on minor errors
        # Check session first
        if 'user_id' not in session:
            flash('Please login to create an invitation', 'error')
            return redirect(url_for('auth'))
        
        # Verify user still exists in database and session is valid
        try:
            user_id = session.get('user_id')
            if not user_id:
                flash('Please login to create an invitation', 'error')
                return redirect(url_for('auth'))
            
            # Verify user exists in database - but don't clear session on first check failure
            current_user = User.query.get(user_id)
            if not current_user:
                app.logger.warning(f"User not found for session user_id: {user_id}, but session exists")
                # Only clear session if user definitely doesn't exist
                session.clear()
                flash('Session expired. Please login again.', 'error')
                return redirect(url_for('auth'))
            
            # Refresh session to prevent timeout - only if user is valid
            session['user_id'] = user_id
            session.permanent = True
            
        except KeyError:
            # KeyError means session doesn't have user_id, but don't clear if it might be valid
            if 'user_id' not in session:
                flash('Please login to create an invitation', 'error')
                return redirect(url_for('auth'))
        except Exception as e:
            app.logger.error(f"Error getting user: {str(e)}")
            # Don't clear session on database errors - might be temporary
            flash('Error retrieving user information. Please try again.', 'error')
            # Only redirect if it's a critical error
            if 'user_id' not in session:
                return redirect(url_for('auth'))
        
        # Get template and event_type parameters
        selected_template = request.args.get('template')
        template_id = request.args.get('template_id')  # Template ID from database
        event_type = request.args.get('event_type', 'birthday')  # Default to birthday
        
        # If no template is selected, redirect to templates page to select event and template first
        if not selected_template and not template_id:
            return redirect(url_for('templates'))
        
        # If template_id is provided, fetch the template from database
        selected_template_obj = None
        if template_id:
            try:
                selected_template_obj = Template.query.get(int(template_id))
                if selected_template_obj:
                    selected_template = selected_template_obj.name
                    event_type = selected_template_obj.event_type  # Use template's event type
            except (ValueError, TypeError):
                pass
        
        # Fetch templates for the selected event type - Only templates with images from templatesimages/
        templates = Template.query.filter_by(event_type=event_type, is_active=True)\
            .filter(Template.preview_image.like('/images/templatesimages/%'))\
            .order_by(Template.name.asc()).all()
        
        # Also fetch all active templates for theme selection page - Only with templatesimages/
        all_templates = Template.query.filter_by(is_active=True)\
            .filter(Template.preview_image.like('/images/templatesimages/%'))\
            .order_by(Template.event_type.asc(), Template.name.asc()).all()
        
        # Optimize: Only fetch active event types
        event_types = EventType.query.filter_by(is_active=True).order_by(EventType.sort_order.asc()).limit(10).all()
        
        # Determine which step to show
        # If template is selected, go directly to details form, otherwise show theme selection
        show_details = bool(selected_template or template_id)
        
        return render_template('invitation/create.html', 
                             event_types=event_types, 
                             selected_template=selected_template,
                             selected_template_obj=selected_template_obj,
                             template_id=template_id if 'template_id' in locals() else None,
                             templates=templates,
                             all_templates=all_templates,
                             event_type=event_type,
                             current_user=current_user,
                             show_details=show_details)

    @app.route('/create-invitation', methods=['POST'])
    def create_invitation_post():
        # Improved authentication check - less aggressive, don't clear session on minor errors
        if 'user_id' not in session:
            flash('Please login to create an invitation', 'error')
            return redirect(url_for('auth'))
        
        # Verify user exists - but don't clear session on first check failure
        try:
            user_id = session.get('user_id')
            if not user_id:
                flash('Please login to create an invitation', 'error')
                return redirect(url_for('auth'))
            
            current_user = User.query.get(user_id)
            if not current_user:
                app.logger.warning(f"User not found for session user_id: {user_id}, but session exists")
                # Only clear session if user definitely doesn't exist
                session.clear()
                flash('Session expired. Please login again.', 'error')
                return redirect(url_for('auth'))
            
            # Refresh session to prevent timeout - only if user is valid
            session['user_id'] = user_id
            session.permanent = True
        except Exception as e:
            app.logger.error(f"Error verifying user: {str(e)}")
            # Don't clear session on database errors - might be temporary
            flash('Error retrieving user information. Please try again.', 'error')
            # Only redirect if it's a critical error
            if 'user_id' not in session:
                return redirect(url_for('auth'))

        try:
            data = request.form
            selected_template = data.get('selectedTemplate', '')
            template_id = data.get('templateId', '')
            template_image_url = data.get('templateImageUrl', '')
            
            # Validate required fields
            if not data.get('eventTitle'):
                flash('Event title is required', 'error')
                return redirect(url_for('create_invitation'))
            
            if not data.get('eventDate'):
                flash('Event date is required', 'error')
                return redirect(url_for('create_invitation'))

            # Handle file uploads with better error handling and optimization
            uploaded_files = {}
            gallery_images = []
            
            # Pre-generate timestamp once for all files (performance optimization)
            timestamp = datetime.now().timestamp()
            user_id = session['user_id']

            # Ensure upload directory exists (only once)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            # Main image upload - optimized
            if 'mainImage' in request.files:
                main_file = request.files['mainImage']
                if main_file and main_file.filename and main_file.filename != '':
                    try:
                        filename = secure_filename(f"{user_id}_main_{timestamp}_{main_file.filename}")
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        main_file.save(file_path)
                        uploaded_files['main_image'] = filename
                    except Exception as e:
                        app.logger.error(f"Error saving main image: {str(e)}")

            # Event-specific image uploads - optimized loop
            event_images = ['brideImage', 'groomImage', 'coupleImage', 'birthdayImage', 'graduateImage', 'honoreeImage']
            for img_field in event_images:
                if img_field in request.files:
                    img_file = request.files[img_field]
                    if img_file and img_file.filename and img_file.filename != '':
                        try:
                            field_name = img_field.replace('Image', '').lower()
                            filename = secure_filename(f"{user_id}_{field_name}_{timestamp}_{img_file.filename}")
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            img_file.save(file_path)
                            uploaded_files[f'{field_name}_image'] = filename
                        except Exception as e:
                            app.logger.error(f"Error saving {img_field}: {str(e)}")

            # Gallery images upload - optimized
            if 'galleryImages' in request.files:
                gallery_files = request.files.getlist('galleryImages')
                for i, gallery_file in enumerate(gallery_files):
                    if gallery_file and gallery_file.filename and gallery_file.filename != '':
                        try:
                            filename = secure_filename(f"{user_id}_{timestamp}_{i}_{gallery_file.filename}")
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            gallery_file.save(file_path)
                            gallery_images.append(filename)
                        except Exception as e:
                            app.logger.error(f"Error saving gallery image {i}: {str(e)}")
            
            # Handle voice message upload
            voice_message_url = None
            voice_message_duration = None
            enable_voice_message = False
            if 'voiceMessage' in request.files:
                voice_file = request.files['voiceMessage']
                if voice_file and voice_file.filename and voice_file.filename != '':
                    try:
                        filename = secure_filename(f"voice_{user_id}_{timestamp}_{voice_file.filename}")
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        voice_file.save(file_path)
                        voice_message_url = url_for('uploaded_file', filename=filename)
                        # Estimate duration (15 seconds max)
                        voice_message_duration = 15
                        enable_voice_message = True
                        app.logger.info(f"Voice message saved: {filename}")
                    except Exception as e:
                        app.logger.error(f"Error saving voice message: {str(e)}")

            # Generate share URL before creating invitation (optimization)
            share_url = generate_unique_share_url()
            
            # Parse event date once (optimization)
            event_date = None
            if data.get('eventDate'):
                try:
                    event_date = datetime.strptime(data.get('eventDate', ''), '%Y-%m-%d')
                except ValueError:
                    app.logger.warning(f"Invalid event date format: {data.get('eventDate')}")
            
            # Determine event type from template or fallback
            event_type = 'general'
            if template_id:
                # Get event type from database template
                try:
                    template = Template.query.get(template_id)
                    if template:
                        event_type = template.event_type
                except Exception as e:
                    app.logger.error(f"Error fetching template: {str(e)}")
            elif selected_template:
                # Extract event type from template name
                event_type = selected_template.split('_')[0] if '_' in selected_template else 'general'
            
            # Prepare customization data once (optimization)
            customization_data = json.dumps({
                'font_style': data.get('fontStyle', 'default'),
                'language': data.get('language', 'english'),
                'template_id': template_id,
                'template_image_url': template_image_url
            })
            
            # Create new invitation - optimized
            invitation = Invitation(
                user_id=user_id,
                title=data.get('eventTitle', ''),
                description=data.get('eventDescription', ''),
                event_type=event_type,
                template_name=selected_template,
                event_date=event_date,
                event_style=data.get('eventStyle', ''),
                bride_name=data.get('brideName', ''),
                groom_name=data.get('groomName', ''),
                muhurtham_time=data.get('muhurthamTime', ''),
                reception_time=data.get('receptionTime', ''),
                
                birthday_person=data.get('birthdayPerson', ''),
                age=data.get('age', ''),
                start_time=data.get('startTime', ''),
                dinner_time=data.get('dinnerTime', ''),
                
                mother_name=data.get('motherName', ''),
                father_name=data.get('fatherName', ''),
                babyshower_start_time=data.get('babyshowerStartTime', ''),
                babyshower_end_time=data.get('babyshowerEndTime', ''),
                
                graduate_name=data.get('graduateName', ''),
                degree=data.get('degree', ''),
                school=data.get('school', ''),
                major=data.get('major', ''),
                
                couple_names=data.get('coupleNames', ''),
                marriage_years=data.get('marriageYears', ''),
                anniversary_dinner_time=data.get('anniversaryDinnerTime', ''),
                party_time=data.get('partyTime', ''),
                
                honoree_name=data.get('honoreeName', ''),
                position=data.get('position', ''),
                company=data.get('company', ''),
                start_year=data.get('startYear', ''),
                
                # Contact information
                host_name=data.get('hostName', ''),
                contact_phone=data.get('contactPhone', ''),
                contact_email=data.get('contactEmail', ''),
                venue_address=data.get('venueAddress', ''),
                
                # Story fields
                love_story=data.get('loveStory', ''),
                event_story=data.get('eventStory', ''),
                
                # Image fields
                main_image=uploaded_files.get('main_image'),
                bride_image=uploaded_files.get('bride_image'),
                groom_image=uploaded_files.get('groom_image'),
                birthday_image=uploaded_files.get('birthday_image'),
                couple_image=uploaded_files.get('couple_image'),
                graduate_image=uploaded_files.get('graduate_image'),
                honoree_image=uploaded_files.get('honoree_image'),
                gallery_images=json.dumps(gallery_images) if gallery_images else None,
                
                # Font and language customization
                customization_data=customization_data,
                
                # Generate unique share URL
                share_url=share_url,
                is_active=True,
                view_count=0,
                expires_at=datetime.utcnow() + timedelta(days=365),  # Set expiration to 1 year
                
                # Emotional Features
                enable_personal_messages=data.get('enablePersonalMessages', 'false').lower() == 'true',
                enable_countdown=data.get('enableCountdown', 'true').lower() == 'true',
                countdown_mystery_mode=data.get('countdownMysteryMode', 'false').lower() == 'true',
                enable_voice_message=enable_voice_message,
                voice_message_url=voice_message_url,
                voice_message_duration=voice_message_duration
            )
            
            # Optimized database operations
            db.session.add(invitation)
            try:
                db.session.commit()
                flash('Invitation created successfully!', 'success')
                return redirect(url_for('view_invitation_final', share_url=invitation.share_url))
            except Exception as db_error:
                db.session.rollback()
                app.logger.error(f"Database error creating invitation: {str(db_error)}")
                flash('Error creating invitation. Please try again.', 'error')
                return redirect(url_for('create_invitation'))
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            app.logger.error(f"Error creating invitation: {str(e)}")
            app.logger.error(f"Full traceback: {error_details}")
            db.session.rollback()
            flash(f'Error creating invitation: {str(e)}. Please try again.', 'error')
            return redirect(url_for('create_invitation'))

    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        try:
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        except FileNotFoundError:
            # Return a placeholder image if file not found
            return send_from_directory('static/images', 'developer.jpg')

    @app.route('/static/uploads/<filename>')
    def static_uploaded_file(filename):
        try:
            return send_from_directory('uploads', filename)
        except FileNotFoundError:
            # Return a placeholder image if file not found
            return send_from_directory('static/images', 'developer.jpg')

    @app.route('/test')
    def test():
        return 'Flask app is working!'
    
    @app.route('/service-worker.js')
    def service_worker_redirect():
        """Redirect old service worker path to new location"""
        from flask import redirect
        return redirect('/static/sw.js?v=3', code=301)


    @app.route('/about')
    def about():
        return render_template('about.html')

    @app.route('/contact', methods=['GET', 'POST'])
    def contact():
        if request.method == 'POST':
            # Handle contact form submission
            flash('Thank you for your message! We will get back to you soon.', 'success')
            return redirect(url_for('contact'))
        return render_template('contact.html')

    @app.route('/help')
    def help_center():
        """Help center page"""
        return render_template('help.html')




    # API Routes for Sharing
    @app.route('/api/track-share', methods=['POST'])
    def track_share():
        """Track sharing actions for analytics"""
        try:
            data = request.get_json()
            invitation_id = data.get('invitation_id')
            share_method = data.get('share_method')
            url = data.get('url')
            
            if not invitation_id or not share_method:
                return jsonify({'success': False, 'message': 'Missing required data'}), 400
            
            # Check for duplicate shares from same IP within last 5 minutes
            from datetime import datetime, timedelta
            recent_share = InvitationShare.query.filter(
                InvitationShare.invitation_id == invitation_id,
                InvitationShare.share_method == share_method,
                InvitationShare.ip_address == request.remote_addr,
                InvitationShare.shared_at >= datetime.utcnow() - timedelta(minutes=5)
            ).first()
            
            if recent_share:
                return jsonify({'success': True, 'message': 'Share already tracked recently'})
            
            # Create share record
            share_record = InvitationShare(
                invitation_id=invitation_id,
                share_method=share_method,
                recipient_info='direct_link',
                ip_address=request.remote_addr
            )
            
            db.session.add(share_record)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Share tracked successfully'})
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error tracking share: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to track share'}), 500

    @app.route('/privacy')
    def privacy():
        return render_template('privacy.html')

    @app.route('/terms')
    def terms():
        return render_template('terms.html')

    @app.route('/forgot-password', methods=['POST'])
    def forgot_password():
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email', '').strip()
            
            if not email:
                return jsonify({'success': False, 'message': 'Email is required'})
            
            # Check if user exists
            user = User.query.filter_by(email=email).first()
            if not user:
                return jsonify({'success': False, 'message': 'User not found with this email'})
            
            # Invalidate any existing unused OTPs for this email and purpose
            existing_otps = OTP.query.filter_by(
                email=email,
                purpose='password_reset',
                is_used=False
            ).all()
            
            for existing_otp in existing_otps:
                existing_otp.is_used = True
            
            # Generate and send new OTP
            otp_code = generate_otp()
            otp = OTP(
                email=email,
                otp_code=otp_code,
                purpose='password_reset',
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp)
            db.session.commit()
            
            # Send OTP email - check if email was sent successfully
            email_sent = send_otp_email(email, otp_code, purpose='password_reset')
            
            if not email_sent:
                # If email failed, still allow user to proceed but warn them
                app.logger.warning(f"Password reset OTP email failed to send to {email}, but OTP was generated: {otp_code}")
                return jsonify({
                    'success': True, 
                    'message': 'OTP sent to your email. Please check your inbox and spam folder.'
                })
            else:
                return jsonify({'success': True, 'message': 'OTP sent to your email. Please check your inbox.'})
            
        except Exception as e:
            app.logger.error(f"Forgot password error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to send OTP. Please try again.'})

    @app.route('/verify-reset-otp', methods=['POST'])
    def verify_reset_otp():
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email', '').strip()
            otp_code = data.get('otp', '').strip()
            
            if not email or not otp_code:
                return jsonify({'success': False, 'message': 'Email and OTP are required'})
            
            if len(otp_code) != 6:
                return jsonify({'success': False, 'message': 'OTP must be 6 digits'})
            
            # Find valid OTP
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                purpose='password_reset',
                is_used=False
            ).first()
            
            if not otp:
                return jsonify({'success': False, 'message': 'Invalid OTP. Please check and try again.'})
            
            if otp.expires_at < datetime.utcnow():
                # Mark expired OTP as used
                otp.is_used = True
                db.session.commit()
                return jsonify({'success': False, 'message': 'OTP has expired. Please request a new one.'})
            
            # Mark OTP as used
            otp.is_used = True
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'OTP verified successfully'})
            
        except Exception as e:
            app.logger.error(f"Verify reset OTP error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})

    @app.route('/reset-password', methods=['POST'])
    def reset_password():
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email', '').strip()
            otp_code = data.get('otp', '').strip()
            password = data.get('password', '').strip()
            confirm_password = data.get('confirm_password', '').strip()
            
            if not email or not otp_code or not password or not confirm_password:
                return jsonify({'success': False, 'message': 'All fields are required'})
            
            if password != confirm_password:
                return jsonify({'success': False, 'message': 'Passwords do not match'})
            
            if len(password) < 6:
                return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
            
            # Verify OTP was used (additional security check)
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                purpose='password_reset',
                is_used=True
            ).first()
            
            if not otp:
                return jsonify({'success': False, 'message': 'Invalid or expired OTP. Please request a new one.'})
            
            # Update user password
            user = User.query.filter_by(email=email).first()
            if not user:
                return jsonify({'success': False, 'message': 'User not found'})
            
            user.password_hash = generate_password_hash(password)
            user.updated_at = datetime.utcnow()
            
            # Remove the used OTP
            db.session.delete(otp)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Password reset successfully'})
            
        except Exception as e:
            app.logger.error(f"Reset password error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})

    @app.route('/view-invitation-manage/<share_url>')
    def view_invitation_manage(share_url):
        if not is_authenticated():
            flash('Please login to continue', 'error')
            return redirect(url_for('auth'))

        invitation = Invitation.query.filter_by(share_url=share_url).first()
        if not invitation or invitation.user_id != session['user_id']:
            flash('Invitation not found or access denied', 'error')
            return redirect(url_for('dashboard'))

        # Prepare event_data for management view (same as final view)
        event_data = {
            'eventTitle': invitation.title or 'Event Invitation',
            'eventDescription': invitation.description or '',
            'eventDate': invitation.event_date.strftime('%B %d, %Y') if invitation.event_date else '',
            'eventTime': invitation.muhurtham_time or invitation.start_time or invitation.anniversary_dinner_time or invitation.babyshower_start_time or '',
            'venue': invitation.venue_address or '',
            'address': invitation.venue_address or '',
            'description': invitation.description or '',
            'religiousType': invitation.event_style or 'general',
            'familyName': invitation.title or 'Event Invitation',

            # Wedding specific
            'brideName': invitation.bride_name or '',
            'groomName': invitation.groom_name or '',
            'bridePhoto': invitation.bride_image,
            'groomPhoto': invitation.groom_image,
            'couplePhoto': invitation.couple_image,

            # Birthday specific
            'birthdayPerson': invitation.birthday_person or '',
            'age': invitation.age or '',
            'birthdayPhoto': invitation.birthday_image,

            # Other event types...
            'graduatePhoto': invitation.graduate_image,
            'honoreePhoto': invitation.honoree_image,
            'mainImage': invitation.main_image,
            'galleryImages': json.loads(invitation.gallery_images) if invitation.gallery_images else [],

            # Time and venue data
            'timeData': {
                'muhurthamTime': invitation.muhurtham_time or '',
                'receptionTime': invitation.reception_time or '',
                'startTime': invitation.start_time or '',
                'dinnerTime': invitation.dinner_time or '',
                'partyTime': invitation.party_time or '',
                'anniversaryDinnerTime': invitation.anniversary_dinner_time or '',
                'babyshowerStartTime': invitation.babyshower_start_time or '',
                'babyshowerEndTime': invitation.babyshower_end_time or ''
            },
            'venueData': {
                'venue': invitation.venue_address or '',
                'address': invitation.venue_address or ''
            }
        }

        return render_template('invitation/manage.html', invitation=invitation, event_data=event_data)

    @app.route('/invitation/<share_url>')
    def standalone_invitation(share_url):
        """Standalone invitation view without site navigation"""
        invitation = Invitation.query.filter_by(share_url=share_url).first()
        if not invitation:
            flash('Invitation not found', 'error')
            return redirect(url_for('index'))
        
        # Check if invitation has expired
        if is_invitation_expired(invitation):
            flash('This invitation has expired', 'error')
            return redirect(url_for('index'))
        
        # Increment view count
        invitation.view_count += 1
        db.session.commit()
        
        # Prepare event_data in the format the templates expect
        event_data = {
            'eventTitle': invitation.title or 'Event Invitation',
            'eventDescription': invitation.description or '',
            'eventDate': invitation.event_date.strftime('%B %d, %Y') if invitation.event_date else '',
            'eventTime': invitation.muhurtham_time or invitation.start_time or invitation.anniversary_dinner_time or invitation.babyshower_start_time or '',
            'venue': invitation.venue_address or '',
            'address': invitation.venue_address or '',
            'description': invitation.description or '',
            'religiousType': invitation.event_style or 'general',
            'familyName': invitation.title or 'Event Invitation',
            'eventType': invitation.event_type or 'general',
            
            # Story fields
            'loveStory': invitation.love_story or '',
            'eventStory': invitation.event_story or '',
            
            # Wedding specific
            'brideName': invitation.bride_name or '',
            'groomName': invitation.groom_name or '',
            'bridePhoto': invitation.bride_image,
            'groomPhoto': invitation.groom_image,
            'couplePhoto': invitation.couple_image,
            'brideDescription': 'Beautiful Bride',
            'groomDescription': 'Handsome Groom',
            
            # Birthday specific
            'birthdayPerson': invitation.birthday_person or '',
            'age': invitation.age or '',
            'startTime': invitation.start_time or '',
            'dinnerTime': invitation.dinner_time or '',
            'birthdayPhoto': invitation.birthday_image,
            
            # Baby shower specific
            'motherName': invitation.mother_name or '',
            'fatherName': invitation.father_name or '',
            'startTime': invitation.babyshower_start_time or '',
            'endTime': invitation.babyshower_end_time or '',
            'babyGender': '👶',
            'gender': 'Baby',
            'babyName': 'Little Angel',
            'dueDate': 'Coming Soon',
            
            # Graduation specific
            'graduateName': invitation.graduate_name or '',
            'degree': invitation.degree or '',
            'school': invitation.school or '',
            'major': invitation.major or '',
            'graduatePhoto': invitation.graduate_image,
            
            # Anniversary specific
            'coupleNames': invitation.couple_names or '',
            'marriageYears': invitation.marriage_years or '',
            'husbandName': invitation.couple_names.split('&')[0].strip() if invitation.couple_names and '&' in invitation.couple_names else '',
            'wifeName': invitation.couple_names.split('&')[1].strip() if invitation.couple_names and '&' in invitation.couple_names else '',
            'husbandDescription': 'Loving Husband',
            'wifeDescription': 'Beloved Wife',
            'marriageYear': '1999',
            'firstMilestone': '2005',
            'secondMilestone': '2015',
            
            # Retirement specific
            'honoreeName': invitation.honoree_name or '',
            'position': invitation.position or '',
            'company': invitation.company or '',
            'startYear': invitation.start_year or '',
            'honoreePhoto': invitation.honoree_image,
            
            # Main and Gallery images
            'mainImage': invitation.main_image,
            'galleryImages': json.loads(invitation.gallery_images) if invitation.gallery_images else [],
            
            # Contact info
            'hostName': invitation.host_name or '',
            'contactPhone': invitation.contact_phone or '',
            'contactEmail': invitation.contact_email or '',
            
            # Time and venue data (structured format)
            'timeData': {
                'muhurthamTime': invitation.muhurtham_time or '',
                'receptionTime': invitation.reception_time or '',
                'startTime': invitation.start_time or '',
                'dinnerTime': invitation.dinner_time or '',
                'partyTime': invitation.party_time or '',
                'anniversaryDinnerTime': invitation.anniversary_dinner_time or '',
                'babyshowerStartTime': invitation.babyshower_start_time or '',
                'babyshowerEndTime': invitation.babyshower_end_time or ''
            },
            'venueData': {
                'venue': invitation.venue_address or '',
                'address': invitation.venue_address or ''
            }
        }
        
        # Get template image URL from customization data
        template_image_url = None
        if invitation.customization_data:
            try:
                customization = json.loads(invitation.customization_data)
                template_image_url = customization.get('template_image_url')
            except:
                pass
        
        # Get gallery images - use first gallery image as background if available
        gallery_images_list = json.loads(invitation.gallery_images) if invitation.gallery_images else []
        background_image_url = None
        if gallery_images_list and len(gallery_images_list) > 0:
            # Use first gallery image as background (priority over template image)
            background_image_url = f"/static/uploads/{gallery_images_list[0]}"
        elif template_image_url:
            # Fallback to template image if no gallery images
            background_image_url = template_image_url
        
        return render_template('invitation/standalone.html', 
                             invitation=invitation, 
                             event_data=event_data,
                             background_image_url=background_image_url,
                             template_image_url=template_image_url)

    @app.route('/view-invitation-final/<share_url>')
    def view_invitation_final(share_url):
        """View the final invitation as guests would see it - Optimized"""
        # Optimized query - only fetch what we need
        invitation = Invitation.query.filter_by(share_url=share_url).first()
        if not invitation:
            flash('Invitation not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if invitation has expired
        if is_invitation_expired(invitation):
            flash('This invitation has expired', 'error')
            return redirect(url_for('dashboard'))
        
        # Increment view count if user is not the owner - optimized to avoid unnecessary commits
        if not is_authenticated() or invitation.user_id != session.get('user_id'):
            invitation.view_count += 1
            try:
                db.session.commit()
            except Exception as e:
                app.logger.error(f"Error updating view count: {str(e)}")
                db.session.rollback()
        
        # Prepare event_data in the format the templates expect
        event_data = {
            'eventTitle': invitation.title or 'Event Invitation',
            'eventDescription': invitation.description or '',
            'eventDate': invitation.event_date.strftime('%B %d, %Y') if invitation.event_date else '',
            'eventTime': invitation.muhurtham_time or invitation.start_time or invitation.anniversary_dinner_time or invitation.babyshower_start_time or '',
            'venue': invitation.venue_address or '',
            'address': invitation.venue_address or '',
            'description': invitation.description or '',
            'religiousType': invitation.event_style or 'general',
            'familyName': invitation.title or 'Event Invitation',
            'eventType': invitation.event_type or 'general',
            
            # Story fields
            'loveStory': invitation.love_story or '',
            'eventStory': invitation.event_story or '',
            
            # Wedding specific
            'brideName': invitation.bride_name or '',
            'groomName': invitation.groom_name or '',
            'bridePhoto': invitation.bride_image,  # Use the uploaded image field
            'groomPhoto': invitation.groom_image,
            'couplePhoto': invitation.couple_image,  # Add couple photo
            'brideDescription': 'Beautiful Bride',
            'groomDescription': 'Handsome Groom',
            
            # Birthday specific
            'birthdayPerson': invitation.birthday_person or '',
            'age': invitation.age or '',
            'startTime': invitation.start_time or '',
            'dinnerTime': invitation.dinner_time or '',
            'birthdayPhoto': invitation.birthday_image,
            
            # Baby shower specific
            'motherName': invitation.mother_name or '',
            'fatherName': invitation.father_name or '',
            'startTime': invitation.babyshower_start_time or '',
            'endTime': invitation.babyshower_end_time or '',
            'babyGender': '👶',
            'gender': 'Baby',
            'babyName': 'Little Angel',
            'dueDate': 'Coming Soon',
            
            # Graduation specific
            'graduateName': invitation.graduate_name or '',
            'degree': invitation.degree or '',
            'school': invitation.school or '',
            'major': invitation.major or '',
            'graduatePhoto': invitation.graduate_image,
            
            # Anniversary specific
            'coupleNames': invitation.couple_names or '',
            'marriageYears': invitation.marriage_years or '',
            'husbandName': invitation.couple_names.split('&')[0].strip() if invitation.couple_names and '&' in invitation.couple_names else '',
            'wifeName': invitation.couple_names.split('&')[1].strip() if invitation.couple_names and '&' in invitation.couple_names else '',
            'husbandDescription': 'Loving Husband',
            'wifeDescription': 'Beloved Wife',
            'marriageYear': '1999',
            'firstMilestone': '2005',
            'secondMilestone': '2015',
            
            # Retirement specific
            'honoreeName': invitation.honoree_name or '',
            'position': invitation.position or '',
            'company': invitation.company or '',
            'startYear': invitation.start_year or '',
            'honoreePhoto': invitation.honoree_image,
            
            # Main and Gallery images
            'mainImage': invitation.main_image,
            'galleryImages': json.loads(invitation.gallery_images) if invitation.gallery_images else [],
            
            # Contact info
            'hostName': invitation.host_name or '',
            'contactPhone': invitation.contact_phone or '',
            'contactEmail': invitation.contact_email or '',
            
            # Time and venue data (structured format)
            'timeData': {
                'muhurthamTime': invitation.muhurtham_time or '',
                'receptionTime': invitation.reception_time or '',
                'startTime': invitation.start_time or '',
                'dinnerTime': invitation.dinner_time or '',
                'partyTime': invitation.party_time or '',
                'anniversaryDinnerTime': invitation.anniversary_dinner_time or '',
                'babyshowerStartTime': invitation.babyshower_start_time or '',
                'babyshowerEndTime': invitation.babyshower_end_time or ''
            },
            'venueData': {
                'venue': invitation.venue_address or '',
                'address': invitation.venue_address or ''
            }
        }
        
        # Get template image URL - first try from Template model, then from customization data
        template_image_url = None
        
        # Try to get template image from Template model based on template_name
        if invitation.template_name:
            # Try multiple matching strategies
            template = None
            
            # Strategy 1: Exact match
            template = Template.query.filter_by(name=invitation.template_name).first()
            
            # Strategy 2: Case-insensitive exact match
            if not template:
                template = Template.query.filter(Template.name.ilike(invitation.template_name)).first()
            
            # Strategy 3: Partial match (contains)
            if not template:
                template = Template.query.filter(Template.name.ilike(f'%{invitation.template_name}%')).first()
            
            # Strategy 4: Try matching with underscores/spaces normalized
            if not template:
                normalized_name = invitation.template_name.replace('_', ' ').replace('-', ' ')
                template = Template.query.filter(Template.name.ilike(f'%{normalized_name}%')).first()
            
            # Strategy 5: Try reverse - check if template name contains invitation template_name
            if not template:
                template = Template.query.filter(Template.name.ilike(f'%{invitation.template_name.replace("_", " ")}%')).first()
            
            if template and template.preview_image:
                template_image_url = template.preview_image
                # Normalize the path - ensure it uses /images/ instead of /static/images/
                if template_image_url.startswith('/static/images/'):
                    template_image_url = template_image_url.replace('/static/images/', '/images/')
                elif not template_image_url.startswith('/') and not template_image_url.startswith('http'):
                    template_image_url = f'/images/{template_image_url}'
        
        # Fallback to customization data if template not found in database
        if not template_image_url and invitation.customization_data:
            try:
                customization = json.loads(invitation.customization_data)
                template_image_url = customization.get('template_image_url')
                # Normalize the path
                if template_image_url and template_image_url.startswith('/static/images/'):
                    template_image_url = template_image_url.replace('/static/images/', '/images/')
            except:
                pass
        
        # Get gallery images
        gallery_images_list = json.loads(invitation.gallery_images) if invitation.gallery_images else []
        
        # Set background image - prioritize template image over gallery images
        background_image_url = None
        if template_image_url:
            # Use template image as background (priority)
            background_image_url = template_image_url
        elif gallery_images_list and len(gallery_images_list) > 0:
            # Fallback to first gallery image if no template image
            background_image_url = f"/static/uploads/{gallery_images_list[0]}"
        
        # Check if current user is the creator
        is_creator = is_authenticated() and invitation.user_id == session.get('user_id')
        
        # Get wishes for this invitation
        wishes = Wish.query.filter_by(invitation_id=invitation.id).order_by(Wish.created_at.desc()).all()
        wishes_data = [{
            'id': wish.id,
            'name': wish.name,
            'message': wish.message,
            'created_at': wish.created_at.strftime('%B %d, %Y at %I:%M %p')
        } for wish in wishes]
        
        return render_template('invitation/view_final.html', 
                             invitation=invitation, 
                             event_data=event_data, 
                             is_creator=is_creator,
                             wishes=wishes_data,
                             background_image_url=background_image_url,
                             template_image_url=template_image_url,
                             gallery_images_list=gallery_images_list)

    @app.route('/edit-invitation/<int:invitation_id>', methods=['GET', 'POST'])
    def edit_invitation(invitation_id):
        if not is_authenticated():
            flash('Please login to continue', 'error')
            return redirect(url_for('auth'))
        
        invitation = Invitation.query.get_or_404(invitation_id)
        if invitation.user_id != session['user_id']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            try:
                # Update invitation data
                data = request.form
                
                # Handle file uploads for editing
                uploaded_files = {}
                gallery_images_to_add = []

                # Main image upload
                if 'mainImage' in request.files:
                    main_file = request.files['mainImage']
                    if main_file and main_file.filename:
                        # Remove old main image if exists
                        if invitation.main_image:
                            try:
                                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], invitation.main_image))
                            except OSError:
                                pass # Ignore if file not found
                        filename = secure_filename(f"{session['user_id']}_main_{datetime.now().timestamp()}_{main_file.filename}")
                        main_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        uploaded_files['main_image'] = filename

                # Event-specific image uploads
                event_images = ['brideImage', 'groomImage', 'coupleImage', 'birthdayImage', 'graduateImage', 'honoreeImage']
                for img_field in event_images:
                    if img_field in request.files:
                        img_file = request.files[img_field]
                        if img_file and img_file.filename:
                            field_name = img_field.replace('Image', '').lower()
                            # Remove old image if exists
                            old_image_field = f"{field_name}_image"
                            if getattr(invitation, old_image_field, None):
                                try:
                                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], getattr(invitation, old_image_field)))
                                except OSError:
                                    pass
                            filename = secure_filename(f"{session['user_id']}_{field_name}_{datetime.now().timestamp()}_{img_file.filename}")
                            img_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                            uploaded_files[f'{field_name}_image'] = filename

                # Gallery images upload
                if 'galleryImages' in request.files:
                    gallery_files = request.files.getlist('galleryImages')
                    for i, gallery_file in enumerate(gallery_files):
                        if gallery_file and gallery_file.filename:
                            filename = secure_filename(f"{session['user_id']}_{datetime.now().timestamp()}_{i}_{gallery_file.filename}")
                            gallery_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                            gallery_images_to_add.append(filename)

                # Update basic fields
                invitation.title = data.get('eventTitle', '')
                invitation.description = data.get('eventDescription', '')
                invitation.event_date = datetime.strptime(data.get('eventDate', ''), '%Y-%m-%d') if data.get('eventDate') else None
                
                # Update story fields
                invitation.love_story = data.get('loveStory', '')
                invitation.event_story = data.get('eventStory', '')
                
                # Update event-specific fields based on event type
                if invitation.event_type == 'wedding':
                    invitation.bride_name = data.get('brideName', '')
                    invitation.groom_name = data.get('groomName', '')
                    invitation.muhurtham_time = data.get('muhurthamTime', '')
                    invitation.reception_time = data.get('receptionTime', '')
                elif invitation.event_type == 'birthday':
                    invitation.birthday_person = data.get('birthdayPerson', '')
                    invitation.age = data.get('age', '')
                    invitation.start_time = data.get('startTime', '')
                    invitation.dinner_time = data.get('dinnerTime', '')
                elif invitation.event_type == 'babyshower':
                    invitation.mother_name = data.get('motherName', '')
                    invitation.father_name = data.get('fatherName', '')
                    invitation.babyshower_start_time = data.get('babyshowerStartTime', '')
                    invitation.babyshower_end_time = data.get('babyshowerEndTime', '')
                elif invitation.event_type == 'graduation':
                    invitation.graduate_name = data.get('graduateName', '')
                    invitation.degree = data.get('degree', '')
                    invitation.school = data.get('school', '')
                    invitation.major = data.get('major', '')
                elif invitation.event_type == 'anniversary':
                    invitation.couple_names = data.get('coupleNames', '')
                    invitation.marriage_years = data.get('marriageYears', '')
                    invitation.dinner_time = data.get('anniversaryDinnerTime', '')
                    invitation.party_time = data.get('partyTime', '')
                elif invitation.event_type == 'retirement':
                    invitation.honoree_name = data.get('honoreeName', '')
                    invitation.position = data.get('position', '')
                    invitation.company = data.get('company', '')
                    invitation.start_year = data.get('startYear', '')
                
                # Update contact information
                invitation.host_name = data.get('hostName', '')
                invitation.contact_phone = data.get('contactPhone', '')
                invitation.contact_email = data.get('contactEmail', '')
                invitation.venue_address = data.get('venueAddress', '')
                
                # Update style/religious preference
                invitation.event_style = data.get('eventStyle', '')
                
                # Update image fields
                for key, value in uploaded_files.items():
                    setattr(invitation, key, value)

                # Append new gallery images
                current_gallery = json.loads(invitation.gallery_images) if invitation.gallery_images else []
                current_gallery.extend(gallery_images_to_add)
                invitation.gallery_images = json.dumps(current_gallery) if current_gallery else None
                
                invitation.updated_at = datetime.utcnow()
                db.session.commit()
                
                flash('Invitation updated successfully!', 'success')
                return redirect(url_for('view_invitation_manage', share_url=invitation.share_url))
                
            except Exception as e:
                app.logger.error(f"Error updating invitation: {str(e)}")
                db.session.rollback()
                flash('Error updating invitation. Please try again.', 'error')
        
        # Prepare event_data for editing form (similar to manage view)
        event_data = {
            'eventTitle': invitation.title or '',
            'eventDescription': invitation.description or '',
            'eventDate': invitation.event_date.strftime('%Y-%m-%d') if invitation.event_date else '',
            'eventStyle': invitation.event_style or '',
            'venueAddress': invitation.venue_address or '',
            'hostName': invitation.host_name or '',
            'contactPhone': invitation.contact_phone or '',
            'contactEmail': invitation.contact_email or '',
            
            # Story fields
            'loveStory': invitation.love_story or '',
            'eventStory': invitation.event_story or '',

            # Wedding specific
            'brideName': invitation.bride_name or '',
            'groomName': invitation.groom_name or '',
            'muhurthamTime': invitation.muhurtham_time or '',
            'receptionTime': invitation.reception_time or '',
            'coupleImage': invitation.couple_image,

            # Birthday specific
            'birthdayPerson': invitation.birthday_person or '',
            'age': invitation.age or '',
            'startTime': invitation.start_time or '',
            'dinnerTime': invitation.dinner_time or '',
            'birthdayImage': invitation.birthday_image,

            # Baby shower specific
            'motherName': invitation.mother_name or '',
            'fatherName': invitation.father_name or '',
            'babyshowerStartTime': invitation.babyshower_start_time or '',
            'babyshowerEndTime': invitation.babyshower_end_time or '',

            # Graduation specific
            'graduateName': invitation.graduate_name or '',
            'degree': invitation.degree or '',
            'school': invitation.school or '',
            'major': invitation.major or '',
            'graduateImage': invitation.graduate_image,

            # Anniversary specific
            'coupleNames': invitation.couple_names or '',
            'marriageYears': invitation.marriage_years or '',
            'anniversaryDinnerTime': invitation.anniversary_dinner_time or '',
            'partyTime': invitation.party_time or '',

            # Retirement specific
            'honoreeName': invitation.honoree_name or '',
            'position': invitation.position or '',
            'company': invitation.company or '',
            'startYear': invitation.start_year or '',
            'honoreeImage': invitation.honoree_image,

            # Image fields for display in form
            'mainImage': invitation.main_image,
            'brideImage': invitation.bride_image,
            'groomImage': invitation.groom_image,
            'galleryImages': json.loads(invitation.gallery_images) if invitation.gallery_images else [],
        }
        
        return render_template('invitation/edit.html', invitation=invitation, event_data=event_data)

    @app.route('/delete-invitation/<int:invitation_id>', methods=['DELETE'])
    def delete_invitation(invitation_id):
        if not is_authenticated():
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        try:
            invitation = Invitation.query.get_or_404(invitation_id)

            # Check ownership
            if invitation.user_id != session['user_id']:
                return jsonify({'success': False, 'message': 'Access denied'}), 403

            # Delete associated files
            if invitation.main_image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], invitation.main_image))
                except OSError:
                    pass # Ignore if file not found

            if invitation.bride_image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], invitation.bride_image))
                except OSError:
                    pass

            if invitation.groom_image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], invitation.groom_image))
                except OSError:
                    pass

            if invitation.birthday_image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], invitation.birthday_image))
                except OSError:
                    pass
            
            if invitation.couple_image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], invitation.couple_image))
                except OSError:
                    pass

            if invitation.graduate_image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], invitation.graduate_image))
                except OSError:
                    pass

            if invitation.honoree_image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], invitation.honoree_image))
                except OSError:
                    pass

            # Delete gallery images
            if invitation.gallery_images:
                try:
                    gallery_list = json.loads(invitation.gallery_images)
                    for image in gallery_list:
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image))
                        except OSError:
                            pass
                except Exception as e:
                    app.logger.error(f"Error deleting gallery images for invitation {invitation.id}: {str(e)}")


            # Delete invitation record
            db.session.delete(invitation)
            db.session.commit()

            return jsonify({'success': True, 'message': 'Invitation deleted successfully'})

        except Exception as e:
            app.logger.error(f"Error deleting invitation: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to delete invitation'}), 500

    @app.route('/test-event-types')
    def test_event_types():
        try:
            event_types = EventType.query.all()
            return jsonify({
                'success': True,
                'count': len(event_types),
                'event_types': [{'id': et.id, 'name': et.name} for et in event_types]
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })

    # Wish routes
    @app.route('/add-wish/<share_url>', methods=['POST'])
    def add_wish(share_url):
        """Add a wish to an invitation"""
        try:
            invitation = Invitation.query.filter_by(share_url=share_url).first()
            if not invitation:
                return jsonify({'success': False, 'message': 'Invitation not found'}), 404
            
            data = request.get_json()
            name = data.get('name', '').strip()
            message = data.get('message', '').strip()
            
            if not name or not message:
                return jsonify({'success': False, 'message': 'Name and message are required'}), 400
            
            # Get client IP address
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Check if this IP has already wished for this invitation
            existing_wish = Wish.query.filter_by(
                invitation_id=invitation.id,
                ip_address=client_ip
            ).first()
            
            if existing_wish:
                return jsonify({
                    'success': False, 
                    'message': 'You have already sent a wish for this invitation. Each person can only wish once.',
                    'already_wished': True,
                    'existing_wish': {
                        'name': existing_wish.name,
                        'message': existing_wish.message,
                        'created_at': existing_wish.created_at.strftime('%B %d, %Y at %I:%M %p')
                    }
                }), 400
            
            # Create new wish
            wish = Wish(
                invitation_id=invitation.id,
                name=name,
                message=message,
                ip_address=client_ip
            )
            
            db.session.add(wish)
            db.session.commit()
            
            return jsonify({
                'success': True, 
                'message': 'Wish sent successfully!',
                'wish': {
                    'id': wish.id,
                    'name': wish.name,
                    'message': wish.message,
                    'created_at': wish.created_at.strftime('%B %d, %Y at %I:%M %p')
                }
            })
            
        except Exception as e:
            app.logger.error(f"Error adding wish: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to add wish'}), 500

    @app.route('/check-wish-status/<share_url>', methods=['GET'])
    def check_wish_status(share_url):
        """Check if current IP has already wished for this invitation"""
        try:
            invitation = Invitation.query.filter_by(share_url=share_url).first()
            if not invitation:
                return jsonify({'success': False, 'message': 'Invitation not found'}), 404
            
            # Get client IP address
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Check if this IP has already wished
            existing_wish = Wish.query.filter_by(
                invitation_id=invitation.id,
                ip_address=client_ip
            ).first()
            
            if existing_wish:
                return jsonify({
                    'success': True,
                    'already_wished': True,
                    'existing_wish': {
                        'name': existing_wish.name,
                        'message': existing_wish.message,
                        'created_at': existing_wish.created_at.strftime('%B %d, %Y at %I:%M %p')
                    }
                })
            else:
                return jsonify({
                    'success': True,
                    'already_wished': False
                })
                
        except Exception as e:
            app.logger.error(f"Error checking wish status: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to check wish status'}), 500

    @app.route('/save-rsvp', methods=['POST'])
    def save_rsvp():
        """Save RSVP response"""
        try:
            data = request.get_json()
            invitation_id = data.get('invitation_id')
            share_url = data.get('share_url')
            response = data.get('response')
            timestamp = data.get('timestamp')
            
            if not response:
                return jsonify({'success': False, 'message': 'Missing required fields'}), 400
            
            # Find invitation by ID or share_url
            invitation = None
            if invitation_id:
                invitation = Invitation.query.get(invitation_id)
            elif share_url:
                invitation = Invitation.query.filter_by(share_url=share_url).first()
            
            if not invitation:
                return jsonify({'success': False, 'message': 'Invitation not found'}), 404
            
            # For now, just log the RSVP response
            app.logger.info(f"RSVP Response for invitation {invitation.id}: {response}")
            
            return jsonify({
                'success': True,
                'message': 'RSVP saved successfully'
            })
            
        except Exception as e:
            app.logger.error(f"Error saving RSVP: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to save RSVP'}), 500

    @app.route('/get-wishes/<share_url>')
    def get_wishes(share_url):
        """Get all wishes for an invitation"""
        try:
            invitation = Invitation.query.filter_by(share_url=share_url).first()
            if not invitation:
                return jsonify({'success': False, 'message': 'Invitation not found'}), 404
            
            wishes = Wish.query.filter_by(invitation_id=invitation.id).order_by(Wish.created_at.desc()).all()
            
            wishes_data = [{
                'id': wish.id,
                'name': wish.name,
                'message': wish.message,
                'created_at': wish.created_at.strftime('%B %d, %Y at %I:%M %p')
            } for wish in wishes]
            
            return jsonify({
                'success': True,
                'wishes': wishes_data
            })
            
        except Exception as e:
            app.logger.error(f"Error getting wishes: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to get wishes'}), 500

    # RSVP Management Routes
    @app.route('/invitations/<int:invitation_id>/rsvp')
    def rsvp_manage(invitation_id):
        """RSVP management page for invitation hosts"""
        try:
            if not is_authenticated():
                flash('Please login to manage RSVPs', 'error')
                return redirect(url_for('auth'))
            
            invitation = Invitation.query.get_or_404(invitation_id)
            
            # Check if user owns this invitation
            if invitation.user_id != session['user_id']:
                flash('You do not have permission to manage this invitation.', 'error')
                return redirect(url_for('dashboard'))
            
            # Get guests and RSVP statistics safely
            try:
                guests = Guest.query.filter_by(invitation_id=invitation_id).all()
            except Exception as e:
                app.logger.error(f"Error fetching guests: {str(e)}")
                guests = []
            
            # Calculate RSVP statistics safely
            try:
                total_rsvps = RSVP.query.filter_by(invitation_id=invitation_id).count()
                attending = RSVP.query.filter_by(invitation_id=invitation_id, status='attending').count()
                not_attending = RSVP.query.filter_by(invitation_id=invitation_id, status='not_attending').count()
                maybe = RSVP.query.filter_by(invitation_id=invitation_id, status='maybe').count()
            except Exception as e:
                app.logger.error(f"Error calculating RSVP stats: {str(e)}")
                total_rsvps = 0
                attending = 0
                not_attending = 0
                maybe = 0
            
            rsvp_stats = {
                'attending': attending,
                'not_attending': not_attending,
                'maybe': maybe,
                'pending': max(0, len(guests) - total_rsvps),
                'total_guests': len(guests)
            }
            
            return render_template('invitation/rsvp_manage.html', 
                                 invitation=invitation, 
                                 guests=guests, 
                                 rsvp_stats=rsvp_stats)
        except Exception as e:
            app.logger.error(f"Error in rsvp_manage route: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
            flash('An error occurred while loading RSVP management. Please try again.', 'error')
            return redirect(url_for('dashboard'))

    # API Routes for RSVP Management
    @app.route('/api/invitations/<int:invitation_id>/guests', methods=['POST'])
    def add_guest(invitation_id):
        """Add a new guest to an invitation"""
        if not is_authenticated():
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        invitation = Invitation.query.get_or_404(invitation_id)
        
        # Check if user owns this invitation
        if invitation.user_id != session['user_id']:
            return jsonify({'success': False, 'message': 'Permission denied'}), 403
        
        try:
            data = request.get_json()
            
            guest = Guest(
                invitation_id=invitation_id,
                name=data.get('name'),
                email=data.get('email'),
                phone=data.get('phone'),
                plus_ones=data.get('plus_ones', 0),
                dietary_requirements=data.get('dietary_requirements'),
                notes=data.get('notes')
            )
            
            db.session.add(guest)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Guest added successfully', 'guest_id': guest.id})
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding guest: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to add guest'}), 500

    @app.route('/api/invitations/<int:invitation_id>/guests/<int:guest_id>', methods=['GET'])
    def get_guest_details(invitation_id, guest_id):
        """Get guest details"""
        if not is_authenticated():
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        invitation = Invitation.query.get_or_404(invitation_id)
        
        # Check if user owns this invitation
        if invitation.user_id != session['user_id']:
            return jsonify({'success': False, 'message': 'Permission denied'}), 403
        
        try:
            guest = Guest.query.filter_by(id=guest_id, invitation_id=invitation_id).first()
            
            if not guest:
                return jsonify({'success': False, 'message': 'Guest not found'}), 404
            
            # Convert to dictionary for JSON response
            guest_data = {
                'id': guest.id,
                'name': guest.name,
                'email': guest.email,
                'phone': guest.phone,
                'plus_ones': guest.plus_ones,
                'dietary_requirements': guest.dietary_requirements,
                'notes': guest.notes,
                'rsvp': None
            }
            
            if guest.rsvp:
                guest_data['rsvp'] = {
                    'status': guest.rsvp.status,
                    'response_date': guest.rsvp.response_date.isoformat() if guest.rsvp.response_date else None,
                    'plus_ones_attending': guest.rsvp.plus_ones_attending,
                    'message': guest.rsvp.message
                }
            
            return jsonify({'success': True, 'guest': guest_data})
            
        except Exception as e:
            app.logger.error(f"Error getting guest details: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to get guest details'}), 500

    @app.route('/api/invitations/<int:invitation_id>/guests/<int:guest_id>', methods=['DELETE'])
    def remove_guest(invitation_id, guest_id):
        """Remove a guest from an invitation"""
        if not is_authenticated():
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        invitation = Invitation.query.get_or_404(invitation_id)
        
        # Check if user owns this invitation
        if invitation.user_id != session['user_id']:
            return jsonify({'success': False, 'message': 'Permission denied'}), 403
        
        try:
            guest = Guest.query.filter_by(id=guest_id, invitation_id=invitation_id).first()
            
            if not guest:
                return jsonify({'success': False, 'message': 'Guest not found'}), 404
            
            db.session.delete(guest)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Guest removed successfully'})
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error removing guest: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to remove guest'}), 500

    # Public RSVP Response Route - Redirect to invitation view (RSVP handled on page)
    @app.route('/rsvp/<share_url>', methods=['GET'])
    def public_rsvp(share_url):
        """Public RSVP response - redirects to invitation view where RSVP is handled"""
        invitation = Invitation.query.filter_by(share_url=share_url).first_or_404()
        
        # Redirect to the invitation view page where RSVP buttons are handled
        return redirect(url_for('view_invitation_final', share_url=share_url))

    @app.route('/analytics')
    def analytics():
        """General analytics dashboard"""
        try:
            if not is_authenticated():
                flash('Please login to view analytics', 'error')
                return redirect(url_for('auth'))
            
            user_id = session['user_id']
            
            # Get user's invitations
            invitations = Invitation.query.filter_by(user_id=user_id).all()
            
            if not invitations:
                flash('No invitations found. Create your first invitation to see analytics.', 'info')
                return redirect(url_for('dashboard'))
            
            # Calculate overall analytics
            try:
                total_views = sum(invitation.view_count or 0 for invitation in invitations)
                total_guests = sum(len(invitation.guests) if invitation.guests else 0 for invitation in invitations)
                
                # Get shares count safely
                total_shares = 0
                for invitation in invitations:
                    try:
                        total_shares += InvitationShare.query.filter_by(invitation_id=invitation.id).count()
                    except Exception:
                        total_shares += len(invitation.shares) if invitation.shares else 0
                
                # Get RSVP statistics safely
                total_rsvps = 0
                for invitation in invitations:
                    try:
                        total_rsvps += RSVP.query.filter_by(invitation_id=invitation.id).count()
                    except Exception:
                        total_rsvps += len(invitation.rsvps) if invitation.rsvps else 0
                
                rsvp_rate = round((total_rsvps / total_guests * 100) if total_guests > 0 else 0, 1)
            except Exception as e:
                app.logger.error(f"Error calculating analytics: {str(e)}")
                # Set defaults if calculation fails
                total_views = 0
                total_guests = 0
                total_shares = 0
                total_rsvps = 0
                rsvp_rate = 0
            
            # Prepare analytics data
            analytics = {
                'total_invitations': len(invitations),
                'total_views': total_views,
                'total_guests': total_guests,
                'total_rsvps': total_rsvps,
                'total_shares': total_shares,
                'rsvp_rate': rsvp_rate
            }
            
            return render_template('analytics/general.html', 
                                 analytics=analytics, 
                                 invitations=invitations)
        except Exception as e:
            app.logger.error(f"Error in analytics route: {str(e)}")
            import traceback
            app.logger.error(traceback.format_exc())
            flash('An error occurred while loading analytics. Please try again.', 'error')
            return redirect(url_for('dashboard'))

    # Analytics Dashboard Route
    @app.route('/invitations/<int:invitation_id>/analytics')
    def invitation_analytics(invitation_id):
        """Analytics dashboard for invitation performance"""
        if not is_authenticated():
            return redirect(url_for('auth'))
        
        invitation = Invitation.query.get_or_404(invitation_id)
        
        # Check if user owns this invitation
        if invitation.user_id != session['user_id']:
            flash('You do not have permission to view analytics for this invitation.', 'error')
            return redirect(url_for('dashboard'))
        
        try:
            # Get analytics data
            total_views = InvitationView.query.filter_by(invitation_id=invitation_id).count()
            total_guests = Guest.query.filter_by(invitation_id=invitation_id).count()
            total_shares = InvitationShare.query.filter_by(invitation_id=invitation_id).count()
            
            # Calculate RSVP rate
            total_rsvps = RSVP.query.filter_by(invitation_id=invitation_id).count()
            rsvp_rate = round((total_rsvps / total_guests * 100) if total_guests > 0 else 0, 1)
            
            # Get RSVP breakdown
            rsvp_attending = RSVP.query.filter_by(invitation_id=invitation_id, status='attending').count()
            rsvp_not_attending = RSVP.query.filter_by(invitation_id=invitation_id, status='not_attending').count()
            rsvp_maybe = RSVP.query.filter_by(invitation_id=invitation_id, status='maybe').count()
            rsvp_pending = total_guests - total_rsvps
            
            # Get device analytics
            device_views = db.session.query(
                InvitationView.device_type,
                db.func.count(InvitationView.id).label('count')
            ).filter_by(invitation_id=invitation_id).group_by(InvitationView.device_type).all()
            
            device_desktop = next((d.count for d in device_views if d.device_type == 'desktop'), 0)
            device_mobile = next((d.count for d in device_views if d.device_type == 'mobile'), 0)
            device_tablet = next((d.count for d in device_views if d.device_type == 'tablet'), 0)
            
            # Get share analytics
            share_methods = db.session.query(
                InvitationShare.share_method,
                db.func.count(InvitationShare.id).label('count')
            ).filter_by(invitation_id=invitation_id).group_by(InvitationShare.share_method).all()
            
            share_email = next((s.count for s in share_methods if s.share_method == 'email'), 0)
            share_whatsapp = next((s.count for s in share_methods if s.share_method == 'whatsapp'), 0)
            share_facebook = next((s.count for s in share_methods if s.share_method == 'facebook'), 0)
            share_instagram = next((s.count for s in share_methods if s.share_method == 'instagram'), 0)
            share_twitter = next((s.count for s in share_methods if s.share_method == 'twitter'), 0)
            share_telegram = next((s.count for s in share_methods if s.share_method == 'telegram'), 0)
            share_direct = next((s.count for s in share_methods if s.share_method == 'link'), 0)
            share_qr = next((s.count for s in share_methods if s.share_method == 'qr'), 0)
            share_other = total_shares - share_email - share_whatsapp - share_facebook - share_instagram - share_twitter - share_telegram - share_direct - share_qr
            
            # Get recent views (last 10)
            recent_views = InvitationView.query.filter_by(invitation_id=invitation_id)\
                .order_by(InvitationView.viewed_at.desc()).limit(10).all()
            
            # Get top referrers
            top_referrers = db.session.query(
                db.case(
                    (InvitationView.referrer.is_(None), 'direct'),
                    (InvitationView.referrer.like('%mail%'), 'email'),
                    else_='other'
                ).label('source'),
                db.func.count(InvitationView.id).label('views')
            ).filter_by(invitation_id=invitation_id).group_by('source').all()
            
            # Calculate percentages for referrers
            total_referrer_views = sum(r.views for r in top_referrers)
            top_referrers_data = []
            for referrer in top_referrers:
                percentage = round((referrer.views / total_referrer_views * 100) if total_referrer_views > 0 else 0, 1)
                top_referrers_data.append({
                    'source': referrer.source,
                    'views': referrer.views,
                    'percentage': percentage
                })
            
            # Generate sample data for charts (in a real app, this would be actual time-series data)
            import random
            from datetime import datetime, timedelta
            
            # Generate views over time data (last 30 days)
            views_labels = []
            views_data = []
            for i in range(30):
                date = datetime.now() - timedelta(days=29-i)
                views_labels.append(date.strftime('%m/%d'))
                views_data.append(random.randint(0, 20))  # Sample data
            
            # Prepare analytics data
            analytics = {
                'total_views': total_views,
                'total_guests': total_guests,
                'total_shares': total_shares,
                'rsvp_rate': rsvp_rate,
                'views_growth': random.randint(5, 25),  # Sample growth data
                'guests_growth': random.randint(2, 15),
                'rsvp_growth': random.randint(1, 10),
                'shares_growth': random.randint(3, 20),
                'views_labels': views_labels,
                'views_data': views_data,
                'rsvp_attending': rsvp_attending,
                'rsvp_not_attending': rsvp_not_attending,
                'rsvp_maybe': rsvp_maybe,
                'rsvp_pending': rsvp_pending,
                'device_desktop': device_desktop,
                'device_mobile': device_mobile,
                'device_tablet': device_tablet,
                'share_email': share_email,
                'share_whatsapp': share_whatsapp,
                'share_facebook': share_facebook,
                'share_instagram': share_instagram,
                'share_twitter': share_twitter,
                'share_telegram': share_telegram,
                'share_direct': share_direct,
                'share_qr': share_qr,
                'share_other': share_other
            }
            
            # Prepare insights data
            insights = {
                'peak_time': '7:00 PM - 9:00 PM',
                'top_location': 'New York, NY',
                'top_device': 'Mobile (65%)'
            }
            
            return render_template('invitation/analytics.html',
                                 invitation=invitation,
                                 analytics=analytics,
                                 insights=insights,
                                 recent_views=recent_views,
                                 top_referrers=top_referrers_data)
            
        except Exception as e:
            app.logger.error(f"Error loading analytics: {str(e)}")
            flash('Error loading analytics data.', 'error')
            return redirect(url_for('dashboard'))


# End of register_routes function

# Export functions
def export_csv(guests, invitation):
    """Export guest list as CSV"""
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Name', 'Email', 'Phone', 'Plus Ones', 'Status', 'Response Date', 'Dietary Requirements', 'Notes'])
    
    # Write guest data
    for guest in guests:
        status = 'Pending'
        response_date = ''
        if guest.rsvp:
            status = guest.rsvp.status.replace('_', ' ').title()
            if guest.rsvp.response_date:
                response_date = guest.rsvp.response_date.strftime('%Y-%m-%d %H:%M')
        
        writer.writerow([
            guest.name,
            guest.email or '',
            guest.phone or '',
            guest.plus_ones,
            status,
            response_date,
            guest.dietary_requirements or '',
            guest.notes or ''
        ])
    
    output.seek(0)
    
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={invitation.title}_guest_list.csv'}
    )

def export_excel(guests, invitation):
    """Export guest list as Excel"""
    try:
        import pandas as pd
        from io import BytesIO
        
        # Prepare data
        data = []
        for guest in guests:
            status = 'Pending'
            response_date = ''
            if guest.rsvp:
                status = guest.rsvp.status.replace('_', ' ').title()
                if guest.rsvp.response_date:
                    response_date = guest.rsvp.response_date.strftime('%Y-%m-%d %H:%M')
            
            data.append({
                'Name': guest.name,
                'Email': guest.email or '',
                'Phone': guest.phone or '',
                'Plus Ones': guest.plus_ones,
                'Status': status,
                'Response Date': response_date,
                'Dietary Requirements': guest.dietary_requirements or '',
                'Notes': guest.notes or ''
            })
        
        # Create DataFrame and export
        df = pd.DataFrame(data)
        output = BytesIO()
        
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Guest List', index=False)
        
        output.seek(0)
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment; filename={invitation.title}_guest_list.xlsx'}
        )
    except ImportError:
        # Fallback to CSV if pandas is not available
        return export_csv(guests, invitation)

def export_pdf(guests, invitation):
    """Export guest list as PDF"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        from io import BytesIO
        
        output = BytesIO()
        doc = SimpleDocTemplate(output, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph(f"Guest List - {invitation.title}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Prepare table data
        data = [['Name', 'Email', 'Phone', 'Plus Ones', 'Status', 'Response Date']]
        
        for guest in guests:
            status = 'Pending'
            response_date = ''
            if guest.rsvp:
                status = guest.rsvp.status.replace('_', ' ').title()
                if guest.rsvp.response_date:
                    response_date = guest.rsvp.response_date.strftime('%Y-%m-%d')
            
            data.append([
                guest.name,
                guest.email or '',
                guest.phone or '',
                str(guest.plus_ones),
                status,
                response_date
            ])
        
        # Create table
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        doc.build(story)
        output.seek(0)
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={invitation.title}_guest_list.pdf'}
        )
    except ImportError:
        # Fallback to CSV if reportlab is not available
        return export_csv(guests, invitation)

    # ========== EMOTIONAL FEATURES API ENDPOINTS ==========
    
    @app.route('/api/invitations/<share_url>/personal-message', methods=['GET'])
    def get_personal_message(share_url):
        """Get or generate personal message for a guest"""
        try:
            guest_email = request.args.get('guestEmail', '').strip()
            guest_name = request.args.get('guestName', '').strip()
            
            if not guest_email:
                return jsonify({'success': False, 'message': 'Guest email is required'}), 400
            
            invitation = Invitation.query.filter_by(share_url=share_url).first()
            if not invitation:
                return jsonify({'success': False, 'message': 'Invitation not found'}), 404
            
            if not invitation.enable_personal_messages:
                return jsonify({'success': False, 'message': 'Personal messages not enabled'}), 400
            
            # Check if message already exists
            existing_message = PersonalMessage.query.filter_by(
                invitation_id=invitation.id,
                guest_email=guest_email
            ).first()
            
            if existing_message:
                # Mark as viewed
                if not existing_message.viewed_at:
                    existing_message.viewed_at = datetime.utcnow()
                    db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': existing_message.generated_message,
                    'guestName': existing_message.guest_name
                })
            
            # Generate new message
            from utils_emotional import generate_personal_message, get_used_templates_for_invitation
            
            used_templates = get_used_templates_for_invitation(invitation.id, db.session, PersonalMessage)
            message_text, template_combo = generate_personal_message(
                guest_name or guest_email.split('@')[0],
                guest_email,
                invitation.id,
                used_templates
            )
            
            # Save to database
            personal_message = PersonalMessage(
                invitation_id=invitation.id,
                guest_email=guest_email,
                guest_name=guest_name or guest_email.split('@')[0],
                message_template=template_combo,
                generated_message=message_text
            )
            db.session.add(personal_message)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': message_text,
                'guestName': personal_message.guest_name
            })
            
        except Exception as e:
            app.logger.error(f"Error getting personal message: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to get personal message'}), 500
    
    @app.route('/api/invitations/<share_url>/memories', methods=['GET'])
    def get_memories(share_url):
        """Get all memories for an invitation"""
        try:
            invitation = Invitation.query.filter_by(share_url=share_url).first()
            if not invitation:
                return jsonify({'success': False, 'message': 'Invitation not found'}), 404
            
            memories = Memory.query.filter_by(
                invitation_id=invitation.id,
                approved=True
            ).order_by(Memory.uploaded_at.desc()).all()
            
            memories_data = [{
                'id': m.id,
                'guestName': m.guest_name,
                'photoUrl': m.photo_url,
                'memoryText': m.memory_text,
                'uploadedAt': m.uploaded_at.isoformat() if m.uploaded_at else None,
                'likes': m.likes
            } for m in memories]
            
            return jsonify({
                'success': True,
                'memories': memories_data
            })
            
        except Exception as e:
            app.logger.error(f"Error getting memories: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to get memories'}), 500
    
    @app.route('/api/invitations/<share_url>/memories', methods=['POST'])
    def upload_memory(share_url):
        """Upload a memory (photo + text)"""
        try:
            app.logger.info(f"Memory upload request for share_url: {share_url}")
            
            invitation = Invitation.query.filter_by(share_url=share_url).first()
            if not invitation:
                app.logger.warning(f"Invitation not found for share_url: {share_url}")
                return jsonify({'success': False, 'message': 'Invitation not found'}), 404
            
            # Get form data
            guest_name = request.form.get('guestName', '').strip()
            guest_email = request.form.get('guestEmail', '').strip()
            memory_text = request.form.get('memoryText', '').strip()
            
            app.logger.info(f"Memory upload data: guest_name={guest_name}, has_text={bool(memory_text)}")
            
            if not guest_name or not memory_text:
                return jsonify({'success': False, 'message': 'Name and memory text are required'}), 400
            
            # Handle photo upload
            if 'photo' not in request.files:
                app.logger.warning("No 'photo' key in request.files")
                return jsonify({'success': False, 'message': 'Photo is required'}), 400
            
            photo_file = request.files['photo']
            if photo_file.filename == '':
                app.logger.warning("Photo filename is empty")
                return jsonify({'success': False, 'message': 'Photo is required'}), 400
            
            # Ensure upload directory exists
            upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            
            # Save photo
            timestamp = datetime.now().timestamp()
            filename = secure_filename(f"memory_{invitation.id}_{timestamp}_{photo_file.filename}")
            file_path = os.path.join(upload_folder, filename)
            
            try:
                photo_file.save(file_path)
                app.logger.info(f"Photo saved to: {file_path}")
            except Exception as save_error:
                app.logger.error(f"Error saving photo: {str(save_error)}")
                return jsonify({'success': False, 'message': f'Failed to save photo: {str(save_error)}'}), 500
            
            # Create URL for the photo - use direct path if url_for doesn't work
            try:
                photo_url = url_for('uploaded_file', filename=filename, _external=False)
            except:
                # Fallback to direct path
                photo_url = f"/uploads/{filename}"
            
            # Save memory to database
            memory = Memory(
                invitation_id=invitation.id,
                guest_name=guest_name,
                guest_email=guest_email,
                photo_url=photo_url,
                memory_text=memory_text,
                approved=True
            )
            db.session.add(memory)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Memory uploaded successfully',
                'memory': {
                    'id': memory.id,
                    'guestName': memory.guest_name,
                    'guest_name': memory.guest_name,
                    'photoUrl': memory.photo_url,
                    'photo_url': memory.photo_url,
                    'memoryText': memory.memory_text,
                    'memory_text': memory.memory_text,
                    'uploadedAt': memory.uploaded_at.isoformat() if memory.uploaded_at else None,
                    'uploaded_at': memory.uploaded_at.isoformat() if memory.uploaded_at else None,
                    'likes': memory.likes
                }
            })
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            app.logger.error(f"Error uploading memory: {str(e)}")
            app.logger.error(f"Traceback: {error_trace}")
            db.session.rollback()
            
            # Return more detailed error in development, generic in production
            error_message = 'Failed to upload memory'
            if app.config.get('DEBUG', False):
                error_message = f'Failed to upload memory: {str(e)}'
            
            return jsonify({
                'success': False, 
                'message': error_message,
                'error': str(e) if app.config.get('DEBUG', False) else None
            }), 500
    
    @app.route('/api/invitations/<int:invitation_id>/voice-message', methods=['POST'])
    def upload_voice_message(invitation_id):
        """Upload voice message for an invitation"""
        try:
            # Check if user owns the invitation
            if 'user_id' not in session:
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
            invitation = Invitation.query.get(invitation_id)
            if not invitation:
                return jsonify({'success': False, 'message': 'Invitation not found'}), 404
            
            if invitation.user_id != session['user_id']:
                return jsonify({'success': False, 'message': 'Unauthorized'}), 403
            
            # Handle audio file upload
            if 'audio' not in request.files:
                return jsonify({'success': False, 'message': 'Audio file is required'}), 400
            
            audio_file = request.files['audio']
            if audio_file.filename == '':
                return jsonify({'success': False, 'message': 'Audio file is required'}), 400
            
            # Get duration if provided
            duration = request.form.get('duration', type=int)
            
            # Save audio file
            timestamp = datetime.now().timestamp()
            filename = secure_filename(f"voice_{invitation_id}_{timestamp}_{audio_file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            audio_file.save(file_path)
            
            # Create URL for the audio
            audio_url = url_for('uploaded_file', filename=filename)
            
            # Update invitation
            invitation.voice_message_url = audio_url
            invitation.voice_message_duration = duration
            invitation.enable_voice_message = True
            db.session.commit()
            
            return jsonify({
                'success': True,
                'audioUrl': audio_url,
                'duration': duration
            })
            
        except Exception as e:
            app.logger.error(f"Error uploading voice message: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to upload voice message'}), 500