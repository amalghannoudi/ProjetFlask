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
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/ProjetPython'
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
    module_id = db.Column(db.Integer, db.ForeignKey('modules.id'), nullable=False)
    module = db.relationship('Module', backref=db.backref('questions', lazy=True))

# Modèle pour représenter une réponse
class Response(db.Model):
    __tablename__ = 'responses'
    
    id = db.Column(db.Integer, primary_key=True)
    response = db.Column(db.String(500), nullable=False)
    value = db.Column(db.Boolean, nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
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
        elif user.password != password:  
            flash('Mot de passe incorrect.') 
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
        user_email = session['username'] 
        user = Users.query.filter_by(email=user_email).first() 

        if request.method == 'POST':
            score = 0
            total_questions = 0

            # Récupérer les réponses postées
            for key, selected_response in request.form.items():
                question_id = int(key.split('_')[1])
                correct_response = Response.query.filter_by(question_id=question_id, value=True).first()

                if correct_response and selected_response == correct_response.response:
                    score += 1
                total_questions += 1

            final_score = (score / total_questions) * 100 if total_questions > 0 else 0

            # Rediriger vers la page de résultat en passant le nom de l'utilisateur
            return redirect(url_for('result', user_name=user.name, module_name=module_name, score=int(final_score)))  # <-- Fixed here

        module = Module.query.filter_by(title=module_name).first()
        if module:
            questions = Question.query.filter_by(module_id=module.id).all()
            responses = {q.id: Response.query.filter_by(question_id=q.id).all() for q in questions}
            return render_template('quizz.html', module=module, questions=questions, responses=responses)

    return redirect(url_for('login'))

@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    module_name = request.form.get('module_name')  # Example form field
    score = calculate_score()  # Your score calculation logic
    username = get_current_user_name()  # Function to get the current user's name

    return redirect(url_for('result', module_name=module_name, score=score, user_name=username))


@app.route('/<user_name>/<module_name>/result/<int:score>')
def result(user_name, module_name, score):
    return render_template('resultat.html', score=score, module_name=module_name, user_name=user_name)


if __name__ == '__main__':
    app.run(debug=True)
