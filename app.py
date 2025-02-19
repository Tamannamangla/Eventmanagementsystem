from flask import Flask, render_template, redirect, url_for, request, flash,session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import base64


app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    role = db.Column(db.String(15), nullable=False, default='user')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    return render_template('event.html')

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
        if "@" in email_or_username:  # Check if input is an email
            user = User.query.filter(User.email.ilike(email_or_username)).first()  #  Now filtering by email
        else:
            user = User.query.filter(User.username.ilike(email_or_username)).first()  #  Filtering by username

        if user:
            if user.check_password(password):
                login_user(user)
                session['user_id'] = user.id
                session['username'] = user.name  # Store name in session
               # flash("Login successful!", "success")
                return redirect(url_for("home"))
            else:
                flash("Invalid password!", "danger")
        else:
            flash("User not found!", "danger")

        return render_template("login.html", email_or_username=email_or_username)  # Keep input in case of error

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("username", None)  # Remove username from session
    session.pop("user_id", None)
    return redirect(url_for("index"))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        file = request.files.get('profile_picture')
        if file:
            print("Uploaded File Name:", file.filename)  # Debugging

        if file and allowed_file(file.filename): 
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)  # Save the file to the specified folder
            user.profile_picture = filename  # Store the filename in the user's profile
            flash("Profile picture updated successfully!", "success")  # Correct flash message
            #user.profile_picture = file.read()  # Store image as binary data in DB
        else:
            flash("Invalid file format! Only image files are allowed.", "danger")
        user.name = request.form.get('name')
        user.phone = request.form.get('phone')
        user.dob = request.form.get('dob')
        user.gender = request.form.get('gender')
        user.hobbies = request.form.get('hobbies')
        user.bio = request.form.get('bio')
        user.address = request.form.get('address')
        user.social_media = request.form.get('social_media')
        user.notifications = request.form.get('notifications')

        try:
            db.session.commit()  # Save changes
            flash("Profile updated successfully!", "success")
        except Exception as e:
            db.session.rollback()  # Undo changes if an error occurs
            flash(f"Error updating profile: {str(e)}", "danger")

        return redirect(url_for('profile'))  # Reload profile page
    profile_picture = None
    if user.profile_picture:
        profile_picture = base64.b64encode(user.profile_picture).decode('utf-8')

    return render_template('profile.html', user=user, profile_picture=profile_picture)


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route('/submit', methods=['POST'])
def submit():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    message = request.form.get('message')

    # if not name or not email or not phone or not message:
    #     return "Please fill in all fields!", 400  # Bad request

    return render_template('thankyou.html')
# Add Event
@app.route("/admin/add_event", methods=["POST"])
def add_event():
    if "admin" not in session:
        return redirect(url_for("admin_login"))

    title = request.form["title"]
    description = request.form["description"]
    image = request.form["image"]

    new_event = Event(title=title, description=description, image=image)
    db.session.add(new_event)
    db.session.commit()

    return redirect(url_for("admin_dashboard"))

# Delete Event
# @app.route("/admin/delete_event/<int:event_id>")
# def delete_event(event_id):
#     if "admin" not in session:
#         return redirect(url_for("admin_login"))

#     event = Event.query.get(event_id)
#     if event:
#         db.session.delete(event)
#         db.session.commit()

#     return redirect(url_for("admin_dashboard"))
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

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True,port=8080)
