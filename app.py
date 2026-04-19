from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__, static_folder='static')
CORS(app)

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL'}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'Empty URL'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        from scoring import calculate_phishing_score
        result = calculate_phishing_score(url)

        clean = {
            'url':            result['url'],
            'score':          result['score'],
            'risk_level':     result['risk_level'],
            'recommendation': result['recommendation'],
            'details':        result['details'],
            'debug':          result.get('_debug', {}),
            'indicators': {
                'uses_https':         result['raw_results'].get('uses_https'),
                'has_ip':             result['raw_results'].get('has_ip'),
                'has_at_char':        result['raw_results'].get('has_at_char'),
                'suspicious_tld':     result['raw_results'].get('suspicious_tld'),
                'nb_subdomains':      result['raw_results'].get('nb_subdomains'),
                'is_url_shortener':   result['raw_results'].get('is_url_shortener'),
                'dns_exists':         result['raw_results'].get('dns_exists'),
                'recently_created':   result['raw_results'].get('recently_created'),
                'double_extension':   result['raw_results'].get('double_extension'),
                'homograph_chars':    result['raw_results'].get('homograph_chars'),
                'brand_in_subdomain': result['raw_results'].get('brand_in_subdomain'),
                'length':             result['raw_results'].get('length'),
                'ssl_certificate':    result['raw_results'].get('ssl_certificate'),
                'whois':              result['raw_results'].get('whois'),
            }
        }
        return jsonify(clean)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'SnifURL API'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)