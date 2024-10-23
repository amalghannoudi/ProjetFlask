from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "key"
app.permanent_session_lifetime = timedelta(minutes=0.5)

# Configuration de la base de données
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost/projet_QUIZ'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Créez une instance de SQLAlchemy
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)

# Modèle pour représenter un utilisateur
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Formulaire de connexion
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

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

        user = User.query.filter_by(email=email).first()  
        if user is None:
            flash('Ce user n\'existe pas.') 
        elif not check_password_hash(user.password, password):
            flash('Mot de passe incorrect.')  
        else:
            session['username'] = email  # Garder l'email ou le nom d'utilisateur dans la session
            return redirect(url_for('home', user=email))  # Rediriger vers la page d'accueil

    return render_template('login.html', form=form) 

# Page d'inscription
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Vérifiez si l'utilisateur existe déjà
        if User.query.filter_by(email=email).first():
            flash('L\'email est déjà utilisé.')
        else:
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Inscription réussie, veuillez vous connecter.')
            return redirect(url_for('login'))

    return render_template('inscription.html')

# Page d'accueil
@app.route('/home/<user>')
def home(user):
    if 'username' in session:
        return render_template('accueil.html', username=user) 
    else:
        return redirect(url_for('login'))

# Page du quizz
@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if 'username' in session:
        if request.method == 'POST':
            score = 0
            return redirect(url_for('result', score=score))
        return render_template('quizz.html')
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
