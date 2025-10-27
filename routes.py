from flask import render_template, request, jsonify, session, redirect, url_for, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from extensions import db
from models import User, OTP, Invitation, Template, EventType, Wish, Guest, RSVP, InvitationView, InvitationShare
from utils import send_otp_email, generate_otp
from datetime import datetime, timedelta
import json
import random
import string
import os
import requests
from urllib.parse import urlencode
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

def generate_unique_share_url():
    """Generate a unique share URL for invitations"""
    while True:
        # Generate a random 8-character string
        share_url = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        # Check if it already exists
        if not Invitation.query.filter_by(share_url=share_url).first():
            return share_url

def is_invitation_expired(invitation):
    """Check if an invitation has expired"""
    if not invitation.expires_at:
        return False
    return datetime.utcnow() > invitation.expires_at

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
        return send_from_directory('images', filename)

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
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp)
            db.session.commit()
            
            # Send OTP email
            send_otp_email(data['email'], otp_code, purpose='verification')
            
            session['temp_email'] = data['email']
            
            flash('OTP sent to your email. Please check your inbox.', 'success')
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
            otp_code = request.form['otp']
            email = session['temp_email']
            
            # Find the OTP
            otp = OTP.query.filter_by(
                email=email, 
                otp_code=otp_code, 
                is_used=False,
                purpose='verification'
            ).first()
            
            if otp and otp.expires_at > datetime.utcnow():
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
            else:
                flash('Invalid or expired OTP', 'error')
                return redirect(url_for('verify_otp'))
                
        except Exception as e:
            app.logger.error(f"OTP verification error: {str(e)}")
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

    @app.route('/templates')
    def templates():
        # Templates page is public - no login required
        event_types = EventType.query.all()
        return render_template('templates.html', event_types=event_types)

    @app.route('/template-selector-demo')
    def template_selector_demo():
        # Public demo of template selector with images
        # Sample event data for demo
        event_data = {
            'eventTitle': 'Wedding Celebration',
            'eventDate': 'December 25, 2024',
            'eventTime': '6:00 PM',
            'venue': 'Grand Palace Hotel',
            'hostName': 'John & Jane Smith',
            'eventType': 'wedding'
        }
        
        # Create sample templates for demo
        templates = [
            {'id': 1, 'name': 'Wedding Elegant', 'type': 'wedding'},
            {'id': 2, 'name': 'Birthday Fun', 'type': 'birthday'},
            {'id': 3, 'name': 'Anniversary Golden', 'type': 'anniversary'},
            {'id': 4, 'name': 'Baby Shower Sweet', 'type': 'babyshower'}
        ]
        
        return render_template('invitation/template_selector.html', 
                             templates=templates, 
                             event_data=event_data)

    @app.route('/template-selector')
    def template_selector():
        # Template selector page with visual previews
        if not is_authenticated():
            flash('Please login to create an invitation', 'error')
            return redirect(url_for('auth'))
        
        # Get event data from session or create sample data
        event_data = {
            'eventTitle': session.get('event_title', 'Wedding Celebration'),
            'eventDate': session.get('event_date', 'December 25, 2024'),
            'eventTime': session.get('event_time', '6:00 PM'),
            'venue': session.get('venue', 'Grand Palace Hotel'),
            'hostName': session.get('host_name', 'John & Jane Smith'),
            'eventType': session.get('event_type', 'wedding')
        }
        
        # Get available templates
        templates = Template.query.filter_by(is_active=True).all()
        
        return render_template('invitation/template_selector.html', 
                             event_data=event_data, 
                             templates=templates)

    @app.route('/zety-form')
    def zety_form():
        # Zety-style form interface
        return render_template('invitation/zety_style_form.html')

    @app.route('/zety-perfect')
    def zety_perfect():
        # Perfect Zety-style form interface
        return render_template('invitation/zety_perfect_form.html')

    @app.route('/create-invitation')
    def create_invitation():
        if not is_authenticated():
            flash('Please login to create an invitation', 'error')
            return redirect(url_for('auth'))
        
        # Get template parameter if coming from templates page
        selected_template = request.args.get('template')
        
        # Redirect to templates page if no template selected
        if not selected_template:
            flash('Please select a template first to create your invitation', 'info')
            return redirect(url_for('templates'))
        
        # Get current user information
        try:
            current_user = User.query.get(session['user_id'])
            if not current_user:
                app.logger.error(f"User not found for session user_id: {session['user_id']}")
                flash('User not found. Please login again.', 'error')
                session.clear()
                return redirect(url_for('auth'))
            
        except Exception as e:
            app.logger.error(f"Error getting user: {str(e)}")
            flash('Error retrieving user information', 'error')
            return redirect(url_for('auth'))
        
        event_types = EventType.query.all()
        return render_template('invitation/create.html', 
                             event_types=event_types, 
                             selected_template=selected_template,
                             current_user=current_user)

    @app.route('/create-invitation', methods=['POST'])
    def create_invitation_post():
        if not is_authenticated():
            flash('Please login to create an invitation', 'error')
            return redirect(url_for('auth'))

        try:
            data = request.form
            selected_template = data.get('selectedTemplate', '')
            
            # Validate required fields
            if not data.get('eventTitle'):
                flash('Event title is required', 'error')
                return redirect(url_for('create_invitation'))
            
            if not data.get('eventDate'):
                flash('Event date is required', 'error')
                return redirect(url_for('create_invitation'))

            # Handle file uploads with better error handling
            uploaded_files = {}
            gallery_images = []

            # Ensure upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            # Main image upload
            if 'mainImage' in request.files:
                main_file = request.files['mainImage']
                if main_file and main_file.filename and main_file.filename != '':
                    try:
                        filename = secure_filename(f"{session['user_id']}_main_{datetime.now().timestamp()}_{main_file.filename}")
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        main_file.save(file_path)
                        uploaded_files['main_image'] = filename
                    except Exception as e:
                        app.logger.error(f"Error saving main image: {str(e)}")

            # Event-specific image uploads
            event_images = ['brideImage', 'groomImage', 'coupleImage', 'birthdayImage', 'graduateImage', 'honoreeImage']
            for img_field in event_images:
                if img_field in request.files:
                    img_file = request.files[img_field]
                    if img_file and img_file.filename and img_file.filename != '':
                        try:
                            field_name = img_field.replace('Image', '').lower()
                            filename = secure_filename(f"{session['user_id']}_{field_name}_{datetime.now().timestamp()}_{img_file.filename}")
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            img_file.save(file_path)
                            uploaded_files[f'{field_name}_image'] = filename
                        except Exception as e:
                            app.logger.error(f"Error saving {img_field}: {str(e)}")

            # Gallery images upload
            if 'galleryImages' in request.files:
                gallery_files = request.files.getlist('galleryImages')
                for i, gallery_file in enumerate(gallery_files):
                    if gallery_file and gallery_file.filename and gallery_file.filename != '':
                        try:
                            filename = secure_filename(f"{session['user_id']}_{datetime.now().timestamp()}_{i}_{gallery_file.filename}")
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            gallery_file.save(file_path)
                            gallery_images.append(filename)
                        except Exception as e:
                            app.logger.error(f"Error saving gallery image {i}: {str(e)}")

            # Create new invitation
            invitation = Invitation(
                user_id=session['user_id'],
                title=data.get('eventTitle', ''),
                description=data.get('eventDescription', ''),
                event_type=selected_template.split('_')[0] if selected_template else 'general',
                template_name=selected_template,
                event_date=datetime.strptime(data.get('eventDate', ''), '%Y-%m-%d') if data.get('eventDate') else None,
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
                customization_data=json.dumps({
                    'font_style': data.get('fontStyle', 'default'),
                    'language': data.get('language', 'english')
                }),

                # Generate unique share URL
                share_url=generate_unique_share_url(),
                is_active=True,
                view_count=0,
                expires_at=datetime.utcnow() + timedelta(days=365)  # Set expiration to 1 year
            )
            
            db.session.add(invitation)
            db.session.commit()
            
            flash('Invitation created successfully!', 'success')
            return redirect(url_for('view_invitation_final', share_url=invitation.share_url))
            
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

    @app.route('/test-template')
    def test_template():
        return render_template('test_simple.html')

    @app.route('/test-dashboard')
    def test_dashboard():
        return 'Dashboard route is working!'

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


    @app.route('/drag-drop-editor')
    def drag_drop_editor():
        """Drag and drop editor page"""
        return render_template('invitation/drag_drop_editor.html')


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
            
            # Generate and send OTP
            otp_code = generate_otp()
            otp = OTP(
                email=email,
                otp_code=otp_code,
                purpose='password_reset',
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp)
            db.session.commit()
            
            # Send OTP email
            send_otp_email(email, otp_code, purpose='password_reset')
            
            return jsonify({'success': True, 'message': 'OTP sent to your email'})
            
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
            
            # Find valid OTP
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                purpose='password_reset',
                is_used=False
            ).first()
            
            if not otp:
                return jsonify({'success': False, 'message': 'Invalid OTP'})
            
            if otp.expires_at < datetime.utcnow():
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

    @app.route('/view-invitation-final/<share_url>')
    def view_invitation_final(share_url):
        """View the final invitation as guests would see it"""
        invitation = Invitation.query.filter_by(share_url=share_url).first()
        if not invitation:
            flash('Invitation not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if invitation has expired
        if is_invitation_expired(invitation):
            flash('This invitation has expired', 'error')
            return redirect(url_for('dashboard'))
        
        # Increment view count if user is not the owner
        if not is_authenticated() or invitation.user_id != session.get('user_id'):
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
                             wishes=wishes_data)

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
                    invitation.start_time = data.get('babyshowerStartTime', '')
                    invitation.end_time = data.get('babyshowerEndTime', '')
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
            response = data.get('response')
            timestamp = data.get('timestamp')
            
            if not invitation_id or not response:
                return jsonify({'success': False, 'message': 'Missing required fields'}), 400
            
            # Find invitation by share_url (since we're getting it from the URL)
            invitation = Invitation.query.filter_by(share_url=invitation_id).first()
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
        if not is_authenticated():
            return redirect(url_for('login'))
        
        invitation = Invitation.query.get_or_404(invitation_id)
        
        # Check if user owns this invitation
        if invitation.user_id != session['user_id']:
            flash('You do not have permission to manage this invitation.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get guests and RSVP statistics
        guests = Guest.query.filter_by(invitation_id=invitation_id).all()
        
        # Calculate RSVP statistics
        rsvp_stats = {
            'attending': RSVP.query.filter_by(invitation_id=invitation_id, status='attending').count(),
            'not_attending': RSVP.query.filter_by(invitation_id=invitation_id, status='not_attending').count(),
            'maybe': RSVP.query.filter_by(invitation_id=invitation_id, status='maybe').count(),
            'pending': len(guests) - RSVP.query.filter_by(invitation_id=invitation_id).count(),
            'total_guests': len(guests)
        }
        
        return render_template('invitation/rsvp_manage.html', 
                             invitation=invitation, 
                             guests=guests, 
                             rsvp_stats=rsvp_stats)

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

    # Public RSVP Response Route
    @app.route('/rsvp/<share_url>', methods=['GET', 'POST'])
    def public_rsvp(share_url):
        """Public RSVP response page"""
        invitation = Invitation.query.filter_by(share_url=share_url).first_or_404()
        
        if request.method == 'POST':
            try:
                data = request.get_json()
                guest_name = data.get('name')
                status = data.get('status')
                plus_ones_attending = data.get('plus_ones_attending', 0)
                message = data.get('message', '')
                dietary_requirements = data.get('dietary_requirements', '')
                
                # Find or create guest
                guest = Guest.query.filter_by(
                    invitation_id=invitation.id, 
                    name=guest_name
                ).first()
                
                if not guest:
                    # Create new guest if not found
                    guest = Guest(
                        invitation_id=invitation.id,
                        name=guest_name,
                        email=data.get('email', ''),
                        phone=data.get('phone', '')
                    )
                    db.session.add(guest)
                    db.session.flush()  # Get the guest ID
                
                # Create or update RSVP
                rsvp = RSVP.query.filter_by(guest_id=guest.id).first()
                
                if rsvp:
                    # Update existing RSVP
                    rsvp.status = status
                    rsvp.plus_ones_attending = plus_ones_attending
                    rsvp.message = message
                    rsvp.dietary_requirements = dietary_requirements
                    rsvp.response_date = datetime.utcnow()
                    rsvp.ip_address = request.remote_addr
                    rsvp.user_agent = request.headers.get('User-Agent')
                else:
                    # Create new RSVP
                    rsvp = RSVP(
                        invitation_id=invitation.id,
                        guest_id=guest.id,
                        status=status,
                        plus_ones_attending=plus_ones_attending,
                        message=message,
                        dietary_requirements=dietary_requirements,
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent')
                    )
                    db.session.add(rsvp)
                
                db.session.commit()
                
                return jsonify({'success': True, 'message': 'RSVP submitted successfully'})
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error submitting RSVP: {str(e)}")
                return jsonify({'success': False, 'message': 'Failed to submit RSVP'}), 500
        
        # GET request - show RSVP form
        return render_template('invitation/rsvp_simple.html', invitation=invitation)

    # Analytics Dashboard Route
    @app.route('/invitations/<int:invitation_id>/analytics')
    def invitation_analytics(invitation_id):
        """Analytics dashboard for invitation performance"""
        if not is_authenticated():
            return redirect(url_for('login'))
        
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