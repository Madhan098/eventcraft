from app import app
import os

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host_ip = '0.0.0.0'
    print(f"\nEventCraft is running at: http://localhost:{port}")
    print(f"Also accessible via your network IP on port {port}")
    print("Press Ctrl+C to stop\n")
    app.run(host=host_ip, port=port, debug=False)
