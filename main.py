from app import app
import os

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"\nEventCraft is running at: http://localhost:{port}")
    print("Press Ctrl+C to stop\n")
    app.run(host='0.0.0.0', port=port, debug=False)
