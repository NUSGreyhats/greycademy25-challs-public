"""
Web interface for MNIST Digit Classifier (6 vs 7)
Generates session tokens and allows users to upload images for prediction
"""

import os
import uuid
import json
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
DATA_FOLDER = 'data'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ZIP_EXTENSION = 'zip'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

import zipfile


# Model configuration
MODEL_FILE = 'predictor/digit_6_7_classifier.pkl'

app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE


def allowed_file(filename):
    """Check if file extension is allowed (images only)"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_zip_file(filename):
    """Return True if filename has zip extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == ZIP_EXTENSION


def generate_session_token():
    """Generate a unique session token (user ID)"""
    return str(uuid.uuid4())


def get_user_upload_folder(token):
    """Get the upload folder path for a user token: ./data/<token>/uploads/"""
    return os.path.join(DATA_FOLDER, token, 'uploads')


def get_user_thumbnail_folder(token):
    """Get the thumbnail folder path for a user token: ./data/<token>/thumbnails/"""
    return os.path.join(DATA_FOLDER, token, 'thumbnails')


def ensure_user_folder(token):
    """Create user folder structure if it doesn't exist (uploads + thumbnails)"""
    uploads = get_user_upload_folder(token)
    thumbs = get_user_thumbnail_folder(token)
    os.makedirs(uploads, exist_ok=True)
    os.makedirs(thumbs, exist_ok=True)
    return uploads


@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')


@app.route('/api/session', methods=['POST'])
def create_session():
    """Create a new session and return the token"""
    token = generate_session_token()
    ensure_user_folder(token)
    
    return jsonify({
        'success': True,
        'token': token,
        'message': 'Session created successfully'
    })


@app.route('/api/upload/<token>', methods=['POST'])
def upload_image(token):
    """Upload an image or a zip for a specific session (save-only)"""
    # Validate token format (basic UUID validation)
    try:
        uuid.UUID(token)
    except ValueError:
        return jsonify({
            'success': False,
            'error': 'Invalid session token'
        }), 400

    # Check if file is in request
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No file provided'
        }), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400

    try:
        # Ensure user folder exists
        user_folder = ensure_user_folder(token)

        if is_zip_file(file.filename):
            # Save the uploaded zip temporarily
            zip_filename = secure_filename(file.filename)
            zip_path = os.path.join(user_folder, zip_filename)
            file.save(zip_path)

            saved = []
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    for member in zf.infolist():
                        if member.is_dir():
                            continue
                        member_name = member.filename
                        dest_path = os.path.join(user_folder, member_name)

                        with zf.open(member) as member_file, open(dest_path, 'wb') as out_f:
                            out_f.write(member_file.read())

                        saved.append(member_name)
            finally:
                try:
                    os.remove(zip_path)
                except OSError:
                    pass

            if not saved:
                return jsonify({
                    'success': False,
                    'error': 'Zip file contained no supported image files (png,jpg,jpeg,gif)'
                }), 400

            return jsonify({
                'success': True,
                'filenames': saved,
                'message': f'Saved {len(saved)} images from zip'
            })

        else:
            # Single image upload
            if not allowed_file(file.filename):
                return jsonify({
                    'success': False,
                    'error': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'
                }), 400

            # Save file with secure filename
            filename = secure_filename(file.filename)
            file_path = os.path.join(user_folder, filename)
            file.save(file_path)

            return jsonify({
                'success': True,
                'filenames': [filename],
                'message': 'File uploaded'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error saving upload: {str(e)}'
        }), 500


@app.route('/api/session/<token>/images', methods=['GET'])
def get_session_images(token):
    """Get all images uploaded in a session"""
    try:
        uuid.UUID(token)
    except ValueError:
        return jsonify({
            'success': False,
            'error': 'Invalid session token'
        }), 400

    user_folder = get_user_upload_folder(token)

    if not os.path.exists(user_folder):
        return jsonify({
            'success': True,
            'images': []
        })

    images = []
    for filename in os.listdir(user_folder):
        if allowed_file(filename):
            images.append(filename)

    return jsonify({
        'success': True,
        'images': sorted(images)
    })


@app.route('/api/session/<token>/thumbnails/<filename>', methods=['GET'])
def get_thumbnail_file(token, filename):
    """Serve a thumbnail image for a session (read-only; thumbnails only)"""
    try:
        uuid.UUID(token)
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid session token'}), 400

    safe_name = secure_filename(filename)
    # Only allow PNG thumbnails (we create PNG thumbnails)
    if not safe_name.lower().endswith('.png'):
        return jsonify({'success': False, 'error': 'File type not allowed'}), 400

    thumb_folder = get_user_thumbnail_folder(token)
    file_path = os.path.join(thumb_folder, safe_name)
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'error': 'File not found'}), 404

    return send_file(file_path, mimetype='image/png')


@app.route('/api/predict/<token>', methods=['POST'])
def predict_images(token):
    try:
        uuid.UUID(token)
    except ValueError:
        return jsonify({
            'success': False,
            'error': 'Invalid session token'
        }), 400

    user_folder = get_user_upload_folder(token)
    if not os.path.exists(user_folder):
        return jsonify({
            'success': True,
            'results': []
        })

    user_data_path = os.path.join(DATA_FOLDER, token, 'data.json')
    user_data = {}
    try:
        with open(user_data_path, 'r', encoding='utf-8') as f:
            user_data = json.load(f)
    except Exception:
        user_data = {
            'cache': {},
            'token': token,
            'model_path': MODEL_FILE
        }
    
    cache = user_data["cache"]

    filenames = [f for f in os.listdir(user_folder) if allowed_file(f)]

    results = []
    for fname in filenames:
        safe_name = secure_filename(fname)
        file_path = os.path.join(user_folder, safe_name)

        # Return cached result if available
        if safe_name in cache:
            entry = dict(cache[safe_name])
            entry['cached'] = True
            results.append(entry)
            continue

        try:
            out = os.popen(f"python3 predictor/predict.py '{user_data['model_path']}' '{file_path}'").read()
            out = json.loads(out)

            entry = {
                'filename': safe_name,
            } | out

            # Store in cache
            cache[safe_name] = entry
            results.append(entry)
        except Exception as e:
            results.append({'filename': safe_name, 'error': str(e)})

    try:
        tmp_path = user_data_path + '.tmp'
        os.makedirs(os.path.dirname(user_data_path), exist_ok=True)
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, indent=2)
        os.replace(tmp_path, user_data_path)
    except Exception as e:
        # Log the cache write error but do not fail the request
        print(f"Warning: failed to write cache for {token}: {e}")

    return jsonify({
        'success': True,
        'results': results,
    })


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return jsonify({
        'success': False,
        'error': f'File too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024:.1f}MB'
    }), 413


if __name__ == '__main__':
    # Create data folder
    os.makedirs(DATA_FOLDER, exist_ok=True)
    
    # Run the Flask app
    app.run(debug=False, host='0.0.0.0', port=5000)
