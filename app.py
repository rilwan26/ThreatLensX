from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import SecurityScanner
import traceback

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'API is running'})

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start security scan"""
    try:
        data = request.get_json()
        target_url = data.get('url')
        scan_depth = data.get('depth', 2)
        use_tor = data.get('use_tor', False)
        
        if not target_url:
            return jsonify({'error': 'No target URL provided'}), 400
        
        # Initialize scanner
        scanner = SecurityScanner(use_tor=use_tor)
        
        # Perform scan
        results = scanner.full_scan(target_url, scan_depth)
        
        return jsonify(results), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'message': 'Scan failed'
        }), 500

@app.route('/api/tor/status', methods=['GET'])
def tor_status():
    """Check Tor connection status"""
    try:
        from scanner import TorManager
        tor_manager = TorManager()
        
        if tor_manager.setup_tor_session():
            ip_info = tor_manager.get_tor_ip()
            return jsonify({
                'connected': True,
                'ip_info': ip_info
            })
        else:
            return jsonify({'connected': False})
    except Exception as e:
        return jsonify({
            'connected': False,
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
