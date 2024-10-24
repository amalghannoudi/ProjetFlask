from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "key"
app.permanent_session_lifetime = timedelta(minutes=10)

# Configuration de la base de données pour PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/ProjetPython'  # Modifiez le nom d'utilisateur et le mot de passe si nécessaire
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Créez une instance de SQLAlchemy
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)

# Modèle pour représenter un utilisateur
class Users(db.Model):
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), primary_key=True, unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"

# Modèle pour représenter un module
class Module(db.Model):
    __tablename__ = 'modules'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, )
    image = db.Column(db.String(200), nullable=False)
# Modèle pour représenter une question
class Question(db.Model):
    __tablename__ = 'questions'
    
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    module_id = db.Column(db.Integer, db.ForeignKey('modules.id'), nullable=False)  # Clé étrangère vers Module
    module = db.relationship('Module', backref=db.backref('questions', lazy=True))

# Modèle pour représenter une réponse
class Response(db.Model):
    __tablename__ = 'responses'
    
    id = db.Column(db.Integer, primary_key=True)
    response = db.Column(db.String(500), nullable=False)
    value = db.Column(db.Boolean, nullable=False)  # True pour correct, False pour incorrect
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)  # Clé étrangère vers Question
    question = db.relationship('Question', backref=db.backref('responses', lazy=True))


# Formulaire de connexion
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

# Formulaire de inscription
class SignupForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Sign Up')

# Créez les tables de la base de données
with app.app_context():
    db.create_all()

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = Users.query.filter_by(email=email).first()  
        if user is None:
            flash('Ce user n\'existe pas.') 
       # elif not check_password_hash(user.password, password):
          #  flash('Mot de passe incorrect.') 
        else:
            session['username'] = email  
            return redirect(url_for('home', user=email))   

    return render_template('login.html', form=form) 

# Page d'inscription
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data  # Get name from form
        email = form.email.data
        password = form.password.data

        # Check if the user already exists
        if Users.query.filter_by(email=email).first():
            flash('The email is already registered.')
        else:
            # Hash the password before saving it
            # hashed_password = generate_password_hash(password, method='sha256')
            new_user = Users(name=name, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))

    return render_template('inscription.html', form=form)


# Page d'accueil
@app.route('/home/<user>', methods=['GET', 'POST'])
def home(user):
    if 'username' in session:
        search_query = request.form.get('search', '')
        if search_query:
            modules = Module.query.filter(Module.title.ilike(f'%{search_query}%')).all()
        else:
            modules = Module.query.all()
        return render_template('accueil.html', username=user, modules=modules, search_query=search_query)
    else:
        return redirect(url_for('login'))

@app.route('/quiz/<module_name>', methods=['GET', 'POST'])
def quiz(module_name):
    if 'username' in session:
        if request.method == 'POST':
            score = 0
            return redirect(url_for('result', score=score))
        
        # Récupérer le module en fonction du nom passé dans l'URL
        module = Module.query.filter_by(title=module_name).first()

        if module:
            return render_template('quizz.html', module=module)
        else:
            flash('Module non trouvé.')
            return redirect(url_for('home', user=session['username']))
    else:
        return redirect(url_for('login'))


# Page de résultat
@app.route('/result/<int:score>')
def result(score):
    if 'username' in session:
        return render_template('result.html', score=score)
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
