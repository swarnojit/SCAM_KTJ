from flask import Flask, request, jsonify, send_from_directory, render_template_string
from flask_cors import CORS
import os
import json
from datetime import datetime

app = Flask(__name__, static_folder='static')
CORS(app)

# Secret key for sessions
app.secret_key = "scamshield-secret-key-2024"

# Import scam detection logic
from scam_core import analyze_message

# ==================== STORAGE (In-Memory for Demo) ====================
# In production, use a proper database
users_db = {
    "demo_user": {
        "phone": "+919876543210",
        "family_members": [
            {"name": "Rahul", "phone": "+919876543210"},
            {"name": "Neha", "phone": "+919123456789"}
        ],
        "recent_scans": [],
        "alerts": [
            {
                "id": 1,
                "type": "danger",
                "title": "Suspicious Message",
                "description": "Asking OTP via SMS",
                "action": "Block & Report",
                "timestamp": datetime.now().isoformat()
            },
            {
                "id": 2,
                "type": "safe",
                "title": "Safe Transaction",
                "description": "Verified payment to 'Utility Co.'",
                "action": "Verified",
                "timestamp": datetime.now().isoformat()
            },
            {
                "id": 3,
                "type": "warning",
                "title": "Unknown Call",
                "description": "Unknown number, urgent tone",
                "action": "Ask My Family",
                "timestamp": datetime.now().isoformat()
            }
        ]
    }
}

# ==================== SERVE HTML FILES ====================

@app.route('/')
def serve_index():
    """Serve login page"""
    return send_from_directory('static', 'index.html')

@app.route('/home.html')
def serve_home():
    """Serve home page"""
    return send_from_directory('static', 'home.html')

@app.route('/check-link.html')
def serve_check_link():
    """Serve check link page"""
    return send_from_directory('static', 'check-link.html')

@app.route('/recent-alerts.html')
def serve_alerts():
    """Serve recent alerts page"""
    return send_from_directory('static', 'recent-alerts.html')

@app.route('/my-family.html')
def serve_family():
    """Serve my family page"""
    return send_from_directory('static', 'my-family.html')

@app.route('/teach-me.html')
def serve_teach():
    """Serve teach me page"""
    return send_from_directory('static', 'teach-me.html')

# ==================== API ENDPOINTS ====================

@app.route('/api/login', methods=['POST'])
def login():
    """Handle login requests"""
    try:
        data = request.get_json()
        phone = data.get('phone', '')
        otp = data.get('otp', '')
        
        # Demo authentication - accept any 6-digit OTP
        if len(otp) == 6 and otp.isdigit():
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user_id': 'demo_user',
                'redirect': '/home.html'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid OTP. Please enter a 6-digit code.'
            }), 401
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({
            'success': False,
            'message': 'Server error during login'
        }), 500

@app.route('/api/scan', methods=['POST'])
def scan():
    """Scan text/link for scams"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'No data provided'
            }), 400
        
        text = data.get('text', '').strip()
        user_id = data.get('user_id', 'demo_user')
        
        if not text:
            return jsonify({
                'error': 'Empty input'
            }), 400
        
        # Analyze the message
        result = analyze_message(text)
        
        # Store in user's recent scans
        if user_id in users_db:
            scan_entry = {
                'text': text,
                'label': result['label'],
                'score': result['risk_score'],
                'reasons': result['reasons'],
                'timestamp': datetime.now().isoformat()
            }
            users_db[user_id]['recent_scans'].insert(0, scan_entry)
            
            # Keep only last 10 scans
            if len(users_db[user_id]['recent_scans']) > 10:
                users_db[user_id]['recent_scans'] = users_db[user_id]['recent_scans'][:10]
            
            # If it's a scam, add to alerts
            if result['risk_score'] >= 40:
                alert = {
                    'id': len(users_db[user_id]['alerts']) + 1,
                    'type': 'danger' if result['risk_score'] >= 70 else 'warning',
                    'title': result['label'],
                    'description': text[:50] + '...' if len(text) > 50 else text,
                    'action': 'Block & Report',
                    'timestamp': datetime.now().isoformat()
                }
                users_db[user_id]['alerts'].insert(0, alert)
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"Scan error: {e}")
        return jsonify({
            'label': 'ERROR',
            'risk_score': 0,
            'reasons': ['Analysis failed - please try again'],
            'ml_confidence': 0.0
        }), 500

@app.route('/api/recent-scans', methods=['GET'])
def get_recent_scans():
    """Get user's recent scans"""
    try:
        user_id = request.args.get('user_id', 'demo_user')
        
        if user_id in users_db:
            return jsonify({
                'scans': users_db[user_id]['recent_scans']
            }), 200
        else:
            return jsonify({'scans': []}), 200
            
    except Exception as e:
        print(f"Error fetching recent scans: {e}")
        return jsonify({'scans': []}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get user's alerts"""
    try:
        user_id = request.args.get('user_id', 'demo_user')
        
        if user_id in users_db:
            return jsonify({
                'alerts': users_db[user_id]['alerts']
            }), 200
        else:
            return jsonify({'alerts': []}), 200
            
    except Exception as e:
        print(f"Error fetching alerts: {e}")
        return jsonify({'alerts': []}), 500

@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    """Clear all alerts for user"""
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'demo_user')
        
        if user_id in users_db:
            users_db[user_id]['alerts'] = []
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False}), 404
            
    except Exception as e:
        print(f"Error clearing alerts: {e}")
        return jsonify({'success': False}), 500

@app.route('/api/family', methods=['GET'])
def get_family_members():
    """Get user's family members"""
    try:
        user_id = request.args.get('user_id', 'demo_user')
        
        if user_id in users_db:
            return jsonify({
                'family_members': users_db[user_id]['family_members']
            }), 200
        else:
            return jsonify({'family_members': []}), 200
            
    except Exception as e:
        print(f"Error fetching family members: {e}")
        return jsonify({'family_members': []}), 500

@app.route('/api/family/add', methods=['POST'])
def add_family_member():
    """Add a family member"""
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'demo_user')
        name = data.get('name', '')
        phone = data.get('phone', '')
        
        if not name or not phone:
            return jsonify({
                'success': False,
                'message': 'Name and phone are required'
            }), 400
        
        if user_id in users_db:
            new_member = {'name': name, 'phone': phone}
            users_db[user_id]['family_members'].append(new_member)
            return jsonify({
                'success': True,
                'member': new_member
            }), 200
        else:
            return jsonify({'success': False}), 404
            
    except Exception as e:
        print(f"Error adding family member: {e}")
        return jsonify({'success': False}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'ScamGuard API is running',
        'timestamp': datetime.now().isoformat()
    })

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Endpoint not found'
    }), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return jsonify({
        'error': 'Internal server error'
    }), 500

# ==================== FAVICON ====================

@app.route('/favicon.ico')
def favicon():
    """Return empty favicon to prevent 404"""
    return '', 204

# ==================== RUN SERVER ====================

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  ScamGuard AI Backend Starting...")
    print("=" * 60)
    print(f"🌐 Server running at: http://localhost:5000")
    print(f"🔐 Login page: http://localhost:5000/")
    print(f"🔍 API endpoint: http://localhost:5000/api/scan")
    print("=" * 60)
    print("\n📋 Available API Endpoints:")
    print("  POST /api/login - User authentication")
    print("  POST /api/scan - Scan messages for scams")
    print("  GET  /api/recent-scans - Get recent scans")
    print("  GET  /api/alerts - Get user alerts")
    print("  POST /api/alerts/clear - Clear all alerts")
    print("  GET  /api/family - Get family members")
    print("  POST /api/family/add - Add family member")
    print("  GET  /api/health - Health check")
    print("=" * 60)
    
    # Create static directory if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')
        print("📁 Created 'static' directory for HTML files")
    
    # Run the Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=True
    )