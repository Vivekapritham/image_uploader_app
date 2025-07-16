import os
import magic
import re
from urllib.parse import quote
from flask import Flask, request, redirect, flash, render_template_string, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Replace below with your MySQL credentials
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Viveka*1045@localhost/photoapp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Constants
MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH = 8, 16
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png"}

# User model
class User(db.Model):
    __tablename__ = 'users'  # Ensures the table is named 'users' in MySQL
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

# Azure Blob setup
connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
container_name = "photos"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
try:
    container_client = blob_service_client.get_container_client(container_name)
    container_client.get_container_properties()
except Exception:
    container_client = blob_service_client.create_container(container_name)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(file):
    try:
        file.seek(0)
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(file.read(2048))
        file.seek(0)
        return mime_type in ALLOWED_MIME_TYPES
    except Exception:
        return False

def is_authenticated():
    return 'user' in session

def password_valid(password):
    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        return f"Password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters long."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[\W_]', password):
        return "Password must contain at least one special character."
    return None

@app.route("/")
def view_photos():
    if not is_authenticated():
        return redirect(url_for("login"))

    blob_items = container_client.list_blobs()
    gallery = "<div class='photo-grid'>"
    for blob in blob_items:
        blob_url = container_client.get_blob_client(blob.name).url
        safe_blob_id = re.sub(r'\\W+', '_', blob.name)
        encoded_name = quote(blob.name)
        upload_time = blob.creation_time.strftime('%Y-%m-%d %H:%M:%S') if blob.creation_time else "Unknown"
        gallery += f"""
        <div class='photo-card'>
            <div class='img-wrapper'>
                <img src="{blob_url}" alt="{blob.name}" loading="lazy"/>
                <div class='overlay'>
                    <button type="button" data-bs-toggle="modal" data-bs-target="#deleteModal{safe_blob_id}">
                        <i class="bi bi-trash-fill"></i>
                    </button>
                </div>
            </div>
            <div class='photo-info'>
                <p class="photo-name">{blob.name}</p>
                <p class="photo-date">{upload_time}</p>
            </div>
        </div>
        <div class="modal fade" id="deleteModal{safe_blob_id}" tabindex="-1">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Confirm Deletion</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">Delete <strong>{blob.name}</strong>?</div>
                    <div class="modal-footer">
                        <a href="/delete-photo/{encoded_name}" class="btn btn-danger">Delete</a>
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    </div>
                </div>
            </div>
        </div>
        """
    gallery += "</div>" if blob_items else "<p class='text-center my-5 text-muted'>No photos yet. Upload to get started.</p>"

    return render_template_string("""
    <!DOCTYPE html>
    <html><head>
        <title>Photos App</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
        <style>
            body { background: #f0f2f5; font-family: 'Segoe UI'; }
            .navbar { background: linear-gradient(to right, #4361ee, #3a0ca3); }
            .photo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; margin-top: 30px; }
            .photo-card { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
            .img-wrapper { position: relative; aspect-ratio: 4/3; overflow: hidden; }
            .img-wrapper img { width: 100%; height: 100%; object-fit: cover; transition: .3s; }
            .photo-card:hover img { transform: scale(1.05); }
            .overlay { position: absolute; inset: 0; display: flex; justify-content: center; align-items: center;
                       background: rgba(0,0,0,0.4); opacity: 0; transition: .3s; }
            .img-wrapper:hover .overlay { opacity: 1; }
            .overlay button { background: white; border: none; color: red; border-radius: 50%; padding: 8px 10px; font-size: 1.2rem; }
            .photo-info { padding: 10px 15px; }
            .photo-name { font-weight: 500; margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .photo-date { font-size: 12px; color: gray; margin: 0; }
        </style>
    </head><body>
    <nav class="navbar navbar-dark px-3 py-2">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">📸 Photos App</a>
            <span class="text-light me-3">Hello, {{ session.user }}</span>
            <a href="/logout" class="btn btn-light btn-sm">Logout</a>
        </div>
    </nav>
    <div class="container py-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, msg in messages %}
              <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                {{ msg }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form method="post" action="/upload-photos" enctype="multipart/form-data" class="mb-4">
            <div class="input-group">
                <input type="file" name="photos" multiple accept=".jpg,.jpeg,.png" class="form-control" required>
                <button class="btn btn-primary" type="submit"><i class="bi bi-upload"></i> Upload</button>
            </div>
        </form>

        {{ content|safe }}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body></html>
    """, content=gallery)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        error = password_valid(password)

        if error:
            flash(error, "danger")
        elif User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
        else:
            hashed_pw = generate_password_hash(password)
            db.session.add(User(username=username, email=email, password=hashed_pw))
            db.session.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template_string("""
    <html><head><title>Register</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
        function validateEmailForm() {
            const emailInput = document.getElementById("email");
            const email = emailInput.value.trim();
            const emailPattern = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;

            if (!emailPattern.test(email)) {
                alert("Please enter a valid email address.");
                emailInput.focus();
                return false;
            }
            return true;
        }
    </script>
    </head><body class="bg-light">
    <div class="container py-5">
        <div class="card mx-auto p-4" style="max-width: 500px;">
            <h3 class="mb-3 text-center">Register</h3>
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, msg in messages %}
                  <div class="alert alert-{{ category }}">{{ msg }}</div>
                {% endfor %}
              {% endif %}
            {% endwith %}
            <form method="POST" onsubmit="return validateEmailForm()">
                <input class="form-control mb-3" name="username" placeholder="Username" required>
                <input class="form-control mb-3" id="email" name="email" type="email" placeholder="Email" required>
                <input class="form-control mb-3" name="password" type="password" placeholder="Password" required>
                <div class="form-text mb-3">8–16 characters, 1 uppercase, 1 special character.</div>
                <button type="submit" class="btn btn-primary w-100">Register</button>
                <div class="text-center mt-3">
                    <a href="/login">Already have an account?</a>
                </div>
            </form>
        </div>
    </div>
    </body></html>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form["identifier"]  # Can be email or username
        password = request.form["password"]

        # Check if identifier is email
        user = None
        if re.match(r"[^@]+@[^@]+\.[^@]+", identifier):
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()

        if not user:
            flash("User not found. Please register.", "danger")
        elif not check_password_hash(user.password, password):
            flash("Incorrect password. Please try again.", "danger")
        else:
            session["user"] = user.username
            flash("Welcome back! Login successful.", "success")
            return redirect(url_for("view_photos"))

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login | Photosphere</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        <style>
            :root { --primary: #4361ee; --accent: #3a0ca3; }
            body { font-family: 'Segoe UI', system-ui, sans-serif; background: linear-gradient(135deg, var(--primary), var(--accent)); min-height: 100vh; display: flex; align-items: center; }
            .auth-container { background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 15px 30px rgba(0,0,0,0.2); }
            .auth-header { text-align: center; margin-bottom: 2rem; }
            .brand-logo { font-size: 2rem; color: var(--primary); margin-bottom: 0.5rem; }
            .brand-title { font-weight: 700; color: #333; margin-bottom: 0.25rem; }
            .brand-subtitle { color: #6c757d; font-size: 0.9rem; }
            .form-control:focus { box-shadow: 0 0 0 0.25rem rgba(67, 97, 238, 0.25); border-color: var(--primary); }
            .btn-primary { background: var(--primary); border: none; }
            .btn-primary:hover { background: var(--accent); }
            .forgot-password { font-size: 0.85rem; color: #6c757d; }
            .forgot-password:hover { text-decoration: underline; color: var(--accent); }
        </style>
    </head>
    <body>
        <div class="container py-5">
            <div class="row justify-content-center">
                <div class="col-md-8 col-lg-6 col-xl-5">
                    <div class="auth-container p-4 p-md-5">
                        <div class="auth-header">
                            <div class="brand-logo"><i class="bi bi-camera"></i></div>
                            <h3 class="brand-title">Photosphere</h3>
                            <p class="brand-subtitle">Sign in to your account</p>
                        </div>

                        {% with messages = get_flashed_messages(with_categories=true) %}
                            {% if messages %}
                                {% for category, msg in messages %}
                                    <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                                        {{ msg }}
                                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                    </div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}

                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">Email or Username</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="bi bi-person"></i></span>
                                    <input type="text" name="identifier" class="form-control" required>
                                </div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Password</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="bi bi-lock"></i></span>
                                    <input type="password" name="password" class="form-control" required>
                                </div>
                            </div>
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                  <a href="/forgot-password" class="forgot-password">Forgot password?</a>
                            </div>
                            <div class="d-grid mt-2">
                                <button type="submit" class="btn btn-primary py-2">Sign In</button>
                            </div>
                            <div class="text-center mt-3">
                                <a href="/register" class="text-decoration-none">Need an account?</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email.", "danger")
        else:
            # Redirect to a page where user can reset password
            return redirect(url_for("reset_password", email=email))
    return render_template_string("""
    <html>
    <head>
        <title>Forgot Password</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container py-5">
            <div class="card mx-auto p-4" style="max-width: 500px;">
                <h3 class="mb-3 text-center">Forgot Password</h3>
                {% with messages = get_flashed_messages(with_categories=true) %}
                  {% if messages %}
                    {% for category, msg in messages %}
                      <div class="alert alert-{{ category }}">{{ msg }}</div>
                    {% endfor %}
                  {% endif %}
                {% endwith %}
                <form method="POST">
                    <input type="email" name="email" class="form-control mb-3" placeholder="Enter your email" required>
                    <button type="submit" class="btn btn-primary w-100">Reset Password</button>
                    <div class="text-center mt-3">
                        <a href="/login">Back to Login</a>
                    </div>
                </form>
            </div>
        </div>
    </body>
    </html>
    """)


@app.route("/reset-password/<email>", methods=["GET", "POST"])
def reset_password(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        error = password_valid(new_password)

        if error:
            flash(error, "danger")
        elif new_password != confirm_password:
            flash("Passwords do not match.", "danger")
        else:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash("Password updated successfully! Please log in.", "success")
            return redirect(url_for("login"))

    return render_template_string("""
    <html>
    <head>
        <title>Reset Password</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container py-5">
            <div class="card mx-auto p-4" style="max-width: 500px;">
                <h3 class="mb-3 text-center">Reset Password</h3>
                {% with messages = get_flashed_messages(with_categories=true) %}
                  {% if messages %}
                    {% for category, msg in messages %}
                      <div class="alert alert-{{ category }}">{{ msg }}</div>
                    {% endfor %}
                  {% endif %}
                {% endwith %}
                <form method="POST">
                    <input type="password" name="password" class="form-control mb-3" placeholder="New Password" required>
                    <input type="password" name="confirm_password" class="form-control mb-3" placeholder="Confirm Password" required>
                    <div class="form-text mb-3">8–16 characters, 1 uppercase, 1 special character.</div>
                    <button type="submit" class="btn btn-success w-100">Update Password</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    """)


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/upload-photos", methods=["POST"])
def upload_photos():
    if not is_authenticated():
        return redirect(url_for("login"))
    uploaded_files = request.files.getlist("photos")
    if not uploaded_files or uploaded_files[0].filename == "":
        flash("No file selected!", "danger")
        return redirect(url_for("view_photos"))
    count = 0
    for file in uploaded_files:
        if file and allowed_file(file.filename) and validate_image(file):
            try:
                container_client.upload_blob(file.filename, file, overwrite=True)
                count += 1
            except Exception as e:
                flash(f"Upload failed: {file.filename} — {str(e)}", "danger")
        else:
            flash(f"Invalid file: {file.filename}", "danger")
    flash(f"{count} photo(s) uploaded successfully!" if count else "No valid files uploaded.", "success")
    return redirect(url_for("view_photos"))

@app.route("/delete-photo/<path:filename>")
def delete_photo(filename):
    if not is_authenticated():
        return redirect(url_for("login"))
    try:
        container_client.delete_blob(filename)
        flash(f"Deleted {filename}", "success")
    except Exception as e:
        flash(f"Failed to delete {filename}: {str(e)}", "danger")
    return redirect(url_for("view_photos"))

if __name__ == "__main__":
    app.run(debug=True)
