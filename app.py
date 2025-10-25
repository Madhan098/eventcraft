import os
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from extensions import db
import json
import datetime

# Create the app
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get("SESSION_SECRET", "eventcraft-secret-key-2024")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Google OAuth Configuration
# For testing - replace with your actual credentials
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', '835499388459-br178k12amc1foaku2kq17n1sopapcit.apps.googleusercontent.com')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', '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')

# Use the deployed URL for production, localhost for development
if os.environ.get('RENDER'):
    # Running on Render
    app.config['GOOGLE_REDIRECT_URI'] = 'https://eventcraft-aysl.onrender.com/auth/google/callback'
else:
    # Running locally
    app.config['GOOGLE_REDIRECT_URI'] = os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:5000/auth/google/callback')

# Configure session
from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=7)  # Sessions last 7 days

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    # For Render, we need a PostgreSQL database
    # Fallback to SQLite only for local development
    if os.environ.get("FLASK_ENV") != "production":
        db_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'database'))
        os.makedirs(db_dir, exist_ok=True)
        db_file = os.path.join(db_dir, 'eventcraft.db')
        database_url = f'sqlite:///{db_file}'
    else:
        # In production, try to use a default database or give helpful error
        # Don't crash the app, just use a placeholder that will fail gracefully
        database_url = "postgresql://placeholder:placeholder@localhost:5432/placeholder"

# Fix for Render PostgreSQL (convert postgres:// to postgresql://)
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max file size

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize the app with the extension
db.init_app(app)

# Add custom Jinja2 filters
@app.template_filter('fromjson')
def fromjson_filter(value):
    if value:
        return json.loads(value)
    return {}

@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        return json.loads(value)
    return {}

# Add custom Jinja2 functions
@app.template_global('template_exists')
def template_exists(template_path):
    """Check if a template exists"""
    try:
        app.jinja_env.get_template(template_path)
        return True
    except:
        return False

# Add context processor to make session available in templates
@app.context_processor
def inject_session():
    from flask import session
    return dict(session=session)

# Add CORS headers
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Add a simple test route
@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    return {
        'status': 'healthy',
        'message': 'EventCraft API is running',
        'timestamp': str(datetime.datetime.now())
    }

# Import models first
try:
    from models import User, OTP, Invitation, Template, EventType, init_sample_data
except Exception as e:
    print(f"Error importing models: {e}")
    import traceback
    traceback.print_exc()

# Initialize database and sample data
with app.app_context():
    try:
        # Check if tables exist, create them if they don't
        inspector = db.inspect(db.engine)
        existing_tables = inspector.get_table_names()
        
        if not existing_tables:
            db.create_all()
            # Initialize sample data only for new database
            init_sample_data()
            
    except Exception as e:
        print(f"Database initialization error: {e}")

# Import routes and register them
try:
    from routes import register_routes
    register_routes(app)
except ImportError as e:
    print(f"Failed to import routes: {e}")
    raise
except Exception as e:
    print(f"Failed to register routes: {e}")
    raise

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)