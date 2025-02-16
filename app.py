from flask import Flask, render_template, redirect, url_for, request, flash,session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

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
def home():
    if 'username' in session:
        return render_template("home.html", username=session["username"])
    return render_template("index.html", username=None)


@app.route('/event')
def event():
    return render_template('event.html')


@app.route('/party1')
def party1():
    return render_template('retirementparty/party1.html')

@app.route('/birthday1')
def birthday1():
    return render_template('birthday/birthday1.html')

@app.route('/birthday2')
def birthday2():
    return render_template('birthday/birthday2.html')

@app.route('/birthday3')
def birthday3():
    return render_template('birthday/birthday3.html')

@app.route('/wed1')
def wed1():
    return render_template('weedings/wed1.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Extract form data
        name = request.form.get("name")
        username = request.form.get("username")  # Added username field
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        phone = request.form.get("phone")  # Changed from 'mobile' to 'phone' to match the form
        gender = request.form.get("gender")  # Added gender field
        dob = request.form.get("dob")  # Added date of birth field
        hobbies = request.form.get("hobbies")  # Added hobbies field
        # role = request.form.get("role", "user")  # Default role is 'user'

        # Validate password match
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))
        
        if len(phone) < 10 or not phone.isdigit():  # Ensure phone number is at least 10 digits and contains only numbers
            flash("Phone number must be at least 10 digits and contain only numbers.", "danger")
            return redirect(url_for("register"))

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))
        
        # if User.query.filter_by(phone=phone).first():
        #     flash("Phone number already exists!", "danger")
        #     return redirect(url_for("register"))

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
            # role=role
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
        email_or_username = request.form.get("email_or_username")
        password = request.form.get("password")

        # Check if the input is an email or username
        if "@" in email_or_username:
            user = User.query.filter_by(email=email_or_username).first()
        else:
            user = User.query.filter_by(username=email_or_username).first()

        # Debugging: Print the user object
        print(f"User: {user}")

        # Check if the user exists and the password is correct
        if user is not None and user.check_password(password):
            login_user(user)
            # session.pop('_flashes', None)
            session['user_id'] = user.id
            session['username'] = user.name  # Store name in session
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "danger")
            return render_template("login.html")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("user_id", None)
    session.pop("username", None)  # Remove username from session
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")



@app.route('/photo')
def photo():
    return render_template('photo.html')

@app.route('/video')
def video():
    return render_template('video.html')

with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
