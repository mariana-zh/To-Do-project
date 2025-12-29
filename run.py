#moduls import
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
load_dotenv()

#our app creation
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
db = SQLAlchemy(app)

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max = 15)])
    email = StringField("email", validators=[DataRequired(), Email()])
    password = PasswordField("password", validators=[DataRequired()])
    password2 = PasswordField("password", validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('sign in')

class Login(FlaskForm): 
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    email =db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False)
    points = db.Column(db.Integer, default = 0)
    tasks = db.relationship('Task', backref='author', lazy=True)
    def __repr__(self ):
        return (f"name: {self.username}, email: {self.email}")
    

class Task(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(60), nullable = False)
    content = db.Column(db.String(130), nullable = True)
    date_posted = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)
    status = db.Column(db.Boolean, default = False, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class TaskForm(FlaskForm):
    title = StringField("task", validators=[DataRequired(), Length(min = 5, max = 120)])
    content = StringField("content", validators=[DataRequired(), Length(min=5, max = 100)])
    submit = SubmitField("Create")

#pages crearion


@app.route("/home", methods = ["GET","POST" ])
@login_required
def home():
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(title = form.title.data, content = form.content.data, author = current_user)
        db.session.add(task)
        db.session.commit()
        flash('task was succsesfully created', "success")
        return redirect(url_for("home"))
    tasks = Task.query.filter_by(author = current_user).order_by(Task.date_posted.desc()).all()
    return render_template("home.html", tasks = tasks, form = form)


@app.route("/task/<int:task_id>/delete", methods = ["POST"])
@login_required
def delete(task_id):
    task = Task.query.get_or_404(task_id)

    if task.author != current_user:
        abort(403)
    current_user.points +=10


    db.session.delete(task)
    db.session.commit()
    if current_user.points >=100:
        flash(f"Amazing work finally you have {current_user.points}")
    else:
        flash("Task was did +10 points ", "info")
    
    return redirect(url_for("home"))
@app.route("/task/<int:task_id>/update", methods = ["GET", "POST"])
@login_required
def update(task_id):
    task = Task.query.get_or_404(task_id)
    if task.author != current_user:
        abort(403)
    
    form = TaskForm()
    if form.validate_on_submit():
        task.title = form.title.data
        task.content = form.content.data
        db.session.commit()
        flash("Task was updated", "success")
        return redirect(url_for("home"))
    elif request.method == "GET":
        form.title.data = task.title
        form.content.data = task.content

    return render_template("home.html", title = "update task", form = form)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/", methods = ["GET","POST" ])
@app.route("/register", methods = ["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user = User(
            username= form.username.data,
            email= form.email.data,
            password = hashed_pw
        )
        
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for("home"))

    return render_template("register.html", title = "Registrarion", form= form)

@app.route('/login', methods = ["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form =Login()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("home"))
        else:
            flash("Sorry try to login again", "danger")
    return render_template("login.html", title = "Login", form = form)

@app.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('register'))
    return redirect(url_for('home'))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/account')
@login_required
def account():
    
    

    return render_template("account.html")
    


#for better work
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

