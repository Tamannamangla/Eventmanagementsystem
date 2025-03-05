from flask import Flask, render_template, redirect, url_for, request, flash,session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import base64
import sqlite3

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'your_secret_key'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150),unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    gender = db.Column(db.String(10), nullable=True)  # Added gender field
    dob = db.Column(db.String(10), nullable=True)  # Added date of birth field
    hobbies = db.Column(db.String(500), nullable=True)  # Added hobbies field
    bio = db.Column(db.Text, nullable=True)  # Ensure bio exists
    address = db.Column(db.String(255), nullable=True)
    social_media = db.Column(db.String(255), nullable=True)
    notifications = db.Column(db.String(50), nullable=True)
    profile_picture = db.Column(db.LargeBinary)  # Add this field in your User model
    role = db.Column(db.String(15), nullable=False, default='User')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # Name of the event
    category = db.Column(db.String(100), nullable=False)  # Category like Birthday, Wedding, etc.
    location = db.Column(db.String(255), nullable=False)  # Location of the event
    date = db.Column(db.String(50), nullable=False)  # Date of the event
    description = db.Column(db.Text, nullable=False)  # Description of the event
    image_url = db.Column(db.String(300))  # URL for event image


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    if 'username' in session:
        return render_template("home.html", username=session["username"])
    return render_template("index.html", username=None)

@app.route('/event')
@login_required
def event():
    event = Event.query.all()
    return render_template("event.html", event=event)
  

@app.route('/birthday1')
@login_required
def birthday1():
    return render_template('birthday/birthday1.html')

@app.route('/birthday2')
@login_required
def birthday2():
    return render_template('birthday/birthday2.html')

@app.route('/birthday3')
@login_required
def birthday3():
    return render_template('birthday/birthday3.html')

@app.route('/party1')
@login_required
def party1():
    return render_template('retirementparty/party1.html')

@app.route('/party2')
@login_required
def party2():
    return render_template('retirementparty/party2.html')

@app.route('/party3')
@login_required
def party3():
    return render_template('retirementparty/party3.html')

@app.route('/wed1')
@login_required
def wed1():
    return render_template('weedings/wed1.html')

@app.route('/wed2')
@login_required
def wed2():
    return render_template('weedings/wed2.html')

@app.route('/wed3')
@login_required
def wed3():
    return render_template('weedings/wed3.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")  # Added username field
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        phone = request.form.get("phone")  
        gender = request.form.get("gender")  # Added gender field
        dob = request.form.get("dob")  # Added date of birth field
        hobbies = request.form.get("hobbies")  # Added hobbies field
        role = request.form.get("role", "user")  # Default role is 'user'

        # Validate password match
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))


        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))

        # Create new user
        new_user = User(
            name=name,
            username=username,  # Added username field
            email=email,
            password_hash= password ,
            phone=phone,  # Ensure this matches your User model
            gender=gender,  # Add this field to your User model if needed
            dob=dob,  # Add this field to your User model if needed
            hobbies=hobbies,  # Add this field to your User model if needed
            role=role
        )
        new_user.set_password(password)  # Hash the password
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    # Render the registration form template for GET requests
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email_or_username = request.form.get("email_or_username", "").strip()
        password = request.form.get("password", "").strip()
        user = None

        # Check if input is an email or username
        if "@" in email_or_username:  
            user = User.query.filter(User.email.ilike(email_or_username.strip())).first()
        else:
            user = User.query.filter(User.username.ilike(email_or_username.strip())).first()


        if user and user.check_password(password):  
            login_user(user)
            session['user_id'] = user.id
            session['username'] = user.name
            session['role'] = user.role

   

            role = user.role.lower()
            if role == 'super_admin':
                return redirect(url_for('super_admin_dashboard'))
            elif role == 'event_manager':
                return redirect(url_for('event_manager_dashboard'))
            elif role == "admin":
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for("home"))

        flash("Invalid username/email or password!", "danger")

    return render_template("login.html")  

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))

    # 🔹 FIXED: Define user_id before using it
    user_id = session['user_id']

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    # 🔹 Fetch user details from the database
    cursor.execute("SELECT name, username, email, phone, dob, gender, hobbies, bio, address, social_media, notifications, profile_picture FROM user WHERE id=?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        conn.close()
        return redirect(url_for('login'))

    user_data = {
        # 'role': user[0] if user[0] else 'user',  # Default role
        'name': user[0], 'username': user[1], 'email': user[2], 'phone': user[3],
        'dob': user[4], 'gender': user[5], 'hobbies': user[6], 'bio': user[7],
        'address': user[8], 'social_media': user[9], 'notifications': user[10],
        'profile_picture': base64.b64encode(user[11]).decode('utf-8') if user[11] else None
    }

    if request.method == "POST":
        name = request.form.get("name")
        phone = request.form.get("phone")
        dob = request.form.get("dob")
        gender = request.form.get("gender")
        hobbies = request.form.get("hobbies")
        bio = request.form.get("bio")
        address = request.form.get("address")
        social_media = request.form.get("social_media")
        notifications = 1 if request.form.get("notifications") else 0

        # Handle Profile Picture Upload
        file = request.files.get("profile_picture")
        profile_pic_data = None

        if file and allowed_file(file.filename): 
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            with open(file_path, "rb") as img_file:
                profile_pic_data = img_file.read()

        # Update User Details
        update_query = """
            UPDATE user 
            SET name=?, phone=?, dob=?, gender=?, hobbies=?, bio=?, address=?, social_media=?, notifications=?
        """
        values = [name, phone, dob, gender, hobbies, bio, address, social_media, notifications]

        # Add profile picture update only if a new picture is uploaded
        if profile_pic_data:
            update_query += ", profile_picture=?"
            values.append(profile_pic_data)

        update_query += " WHERE id=?"
        values.append(user_id)

        cursor.execute(update_query, tuple(values))
        conn.commit()
        conn.close()

        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    conn.close()
    return render_template('profile.html', user=user_data)

@app.route('/admin_profile/<int:user_id>', methods=['GET'])
def admin_profile(user_id):
    if 'user_id' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))

    # Get the logged-in user's ID
    logged_in_user_id = session['user_id']

    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row  # Allow dictionary-like access
    cursor = conn.cursor()

    # Fetch the logged-in user's role
    cursor.execute("SELECT role FROM user WHERE id=?", (logged_in_user_id,))
    logged_in_user = cursor.fetchone()

    if not logged_in_user or logged_in_user['role'] != 'super_admin':
        flash("You are not authorized to view this page!", "error")
        conn.close()
        return redirect(url_for('event_manager_dashboard'))

    # Fetch admin/event manager details
    cursor.execute("""
        SELECT id, role, name, username, email, phone, dob, gender, hobbies, bio, 
               address, social_media, notifications, profile_picture
        FROM user WHERE id=?
    """, (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        conn.close()
        return redirect(url_for('super_admin_dashboard'))

   
    user_data = dict(user)  

    # Encode profile picture if available
    if user_data['profile_picture']:
        user_data['profile_picture'] = base64.b64encode(user_data['profile_picture']).decode('utf-8')

    conn.close()

    # Render the `admin_profile.html` template with user data
    return render_template('admin_profile.html', user=user_data)


#super admin dasboard 
@app.route("/super_admin_dashboard")
@login_required
def super_admin_dashboard():
    
    if "role" not in session or session["role"] != "super_admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("home"))
 
    # Fetch all events from the database
    event = Event.query.all()
    admins = db.session.query(User).filter(User.role == 'admin').all()
    event_managers = db.session.query(User).filter(User.role == 'event_manager').all()


    return render_template("super_admin_dashboard.html", event=event,admins=admins, event_managers=event_managers)

#admin dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if 'user_id' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()

    # Check if logged-in user is an Admin
    cursor.execute("SELECT role FROM user WHERE id=?", (user_id,))
    role = cursor.fetchone()

    if not role or role[0] != 'admin':
        flash("Unauthorized access!", "error")
        conn.close()
        return redirect(url_for('home'))

    # Fetch Event Managers under this Admin
    cursor.execute("SELECT id, name, email, phone FROM user WHERE role='event_manager'")
    event_managers = cursor.fetchall()

    # Fetch all Events (Admins manage all events)
    cursor.execute("SELECT id, name, category, location, date FROM event")
    event = cursor.fetchall()

    conn.close()

    return render_template('admin_dashboard.html', event_managers=event_managers, event=event)

# #event manager dashboard
# @app.route("/dashboard")
# @login_required
# def dashboard():
#     if "role" not in session or session["role"] != "admin":
#         flash("Access denied. Admins only.", "danger")
#         return redirect(url_for("home"))

#     # Fetch all events from the database
#     event = Event.query.all()

#     return render_template("dashboard.html", event=event)

@app.route('/event_manager_dashboard')
@login_required
def event_manager_dashboard():
    if current_user.role != 'event_manager':
        flash("Access denied.", "danger")
        return redirect(url_for('home'))
    event = Event.query.all()
    return render_template('dashboard.html', event=event) 

@app.route('/add_admin', methods=['GET', 'POST'])
@login_required
def add_admin():
    if current_user.role != 'super_admin':
        flash("You are not authorized to perform this action!", "error")
        return redirect(url_for('event_manager_dashboard'))

    if request.method == 'POST':
        name = request.form.get("name")
        username=request.form.get("username")
        phone = request.form.get("phone")
        email = request.form.get("email")
        password = request.form.get("password")
        dob = request.form.get("dob")
        gender = request.form.get("gender")
        hobbies = request.form.get("hobbies")
        bio = request.form.get("bio")
        address = request.form.get("address")
        social_media = request.form.get("social_media")
        notifications = 1 if request.form.get("notifications") else 0
        
       
        role = request.form.get('role')
       

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("An account with this email already exists!", "error")
            return redirect(url_for('add_admin'))

        if role not in ['admin', 'EventManager']:  # Only these roles can be added
            flash("Invalid role selection!", "error")
            return redirect(url_for('add_admin'))
        # ✅ Hash password before storing
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')


        # ✅ Create new admin
        new_admin = User(name=name,username=username, email=email, phone=phone, role=role, password_hash=hashed_password,dob=dob,gender=gender,hobbies=hobbies,bio=bio,address=address,social_media=social_media,notifications=notifications)
        db.session.add(new_admin)
        db.session.commit()

        flash(f"{role} {name} has been added successfully!", "success")
        return redirect(url_for('super_admin_dashboard'))

    return render_template('add_admin.html')

@app.route('/delete_admin/<int:user_id>', methods=['POST'])
@login_required
def delete_admin(user_id):
    # Ensure the current user is a Super Admin
    if current_user.role != 'super_admin':
        flash("You are not authorized to perform this action!", "error")
        return redirect(url_for('event_manager_dashboard'))

    user = User.query.get(user_id)

    if not user:
        flash("User not found!", "error")
        return redirect(url_for('event_manager_dashboard'))

    # Prevent deleting another Super Admin
    if user.role == 'super_admin':
        flash("You cannot delete another Super Admin!", "error")
        return redirect(url_for('event_manager_dashboard'))

    # Delete the user from the database
    db.session.delete(user)
    db.session.commit()
    flash(f"Admin {user.name} has been deleted successfully!", "success")

    return redirect(url_for('super_admin_dashboard'))

@app.route('/submit', methods=['POST'])
def submit():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    message = request.form.get('message')

    return render_template('thankyou.html')

#edit event
@app.route("/edit_event/<int:event_id>", methods=["GET", "POST"])
def edit_event(event_id):
    if "role" not in session or session["role"] not in ["admin", "super_admin", "event_manager"]:
        flash("Access denied!", "danger")
        return redirect(url_for("home"))

    event = Event.query.get(event_id)

    if request.method == "POST":
        event.name = request.form["name"]
        event.category = request.form["category"]
        event.location = request.form["location"]
        event.date = request.form["date"]
        event.description = request.form["description"]
        event.image_url = request.form["image_url"]

        db.session.commit()
        flash("Event updated successfully!", "success")
        return redirect(url_for("event"))

    return render_template("edit_event.html", event=event)

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # Fetch user details
    cursor.execute("SELECT name, username, email, phone, dob, gender, hobbies, bio, address, social_media, notifications, profile_picture FROM user WHERE id=?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        conn.close()
        return redirect(url_for("login"))

    user_data = {
        "name": user[0], "username": user[1], "email": user[2], "phone": user[3],
        "dob": user[4], "gender": user[5], "hobbies": user[6], "bio": user[7],
        "address": user[8], "social_media": user[9], "notifications": user[10],
        "profile_picture": base64.b64encode(user[11]).decode("utf-8") if user[11] else None
    }

    if request.method == "POST":
        name = request.form.get("name")
        phone = request.form.get("phone")
        dob = request.form.get("dob")
        gender = request.form.get("gender")
        hobbies = request.form.get("hobbies")
        bio = request.form.get("bio")
        address = request.form.get("address")
        social_media = request.form.get("social_media")
        notifications = request.form.get("notifications")

        # Handle Profile Picture Upload
        file = request.files.get("profile_picture")
        new_profile_pic = None

        if file and allowed_file(file.filename): 
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            with open(file_path, "rb") as img_file:
                new_profile_pic = img_file.read()

        # Update Query
        update_query = """
            UPDATE user 
            SET name=?, phone=?, dob=?, gender=?, hobbies=?, bio=?, address=?, social_media=?, notifications=?
        """
        values = [name, phone, dob, gender, hobbies, bio, address, social_media, notifications]

        if new_profile_pic:
            update_query += ", profile_picture=?"
            values.append(new_profile_pic)

        update_query += " WHERE id=?"
        values.append(user_id)

        cursor.execute(update_query, tuple(values))
        conn.commit()
        conn.close()

        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    conn.close()
    return render_template("edit_profile.html", user=user_data)

# Delete Event
@app.route("/delete_event/<int:event_id>", methods=["POST"])
def delete_event(event_id):
    if "role" not in session or session["role"] != "admin" or "super_admin" or "event_manager":
        flash("Access denied!", "danger")
        return redirect(url_for("event_manager_dashboard"))

    event = Event.query.get(event_id)
    if event:
        db.session.delete(event)
        db.session.commit()
        flash("Event deleted successfully!", "success")
    else:
        flash("Event not found!", "danger")

    return redirect(url_for("event_manager_dashboard"))

@app.route('/photo')
def photo():
    return render_template('photo.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    feedback_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/thank_you', methods=['POST'])
def thank_you():
    name = request.form['name']
    email = request.form['email']
    feedback_type = request.form['feedback']
    description = request.form['description']

    new_feedback = Feedback(name=name, email=email, feedback_type=feedback_type, description=description)
    db.session.add(new_feedback)
    db.session.commit()

    flash(f'Thank you for your feedback {name}!', 'success')
    return redirect('/feedback')

@app.route('/video')
def video():
    return render_template('video.html')

@app.route('/shorts')
def shorts():
    return render_template('shorts.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error404.html'), 404

@app.route("/add_event", methods=["GET", "POST"])
@login_required  
def add_event():
    if session.get("role") != "admin":
        flash("Access denied! Admins only.", "danger")
        return redirect(url_for("event_manager_dashboard"))  # Redirect normal users

    if request.method == "POST":
        name = request.form.get("name")
        category = request.form.get("category")
        location = request.form.get("location")
        date = request.form.get("date")
        description = request.form.get("description")
        image_url = None  # Default image path

        if "image" in request.files:
            file = request.files["image"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                if not os.path.exists(app.config["UPLOAD_FOLDER"]):
                    os.makedirs(app.config["UPLOAD_FOLDER"])

                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(file_path)
                image_url = file_path  # Save file path in the database
            else:
                image_url = None
        else:
            image_url = None

        # Create a new event object

        new_event = Event(
            name=name,
            category=category,
            location=location,
            date=date,
            description=description,
            image_url=image_url
        )

        db.session.add(new_event)
        db.session.commit()
        flash("Event added successfully!", "success")
        return redirect(url_for("event_manager_dashboard"))  # Redirect to dashboard

    return render_template("add_event.html")

@app.route("/logout")
def logout():
    logout_user()  # Logs out the user from Flask-Login
    session.clear()  # Clears all session data
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("index"))

@app.errorhandler(403)
def forbidden(e):
    return render_template('error403.html'), 403

@app.errorhandler(500)
def server_error(e):
    return render_template('error500.html'), 500

with app.app_context():
    db.create_all()
if __name__ == '__main__':
    app.run(debug=True,port=8080)
