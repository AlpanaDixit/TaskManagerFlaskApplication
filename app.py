from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from flask_jwt_extended import create_access_token, jwt_required,JWTManager, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder="templates")

app.config['SECRET_KEY'] = 'SUPER-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()

class UserRegistration(Resource):
    def post(self):
        # Retrieve JSON data from the request body
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Check if username or password is missing
        if not username or not password:
            return {'message': 'Missing username or password'}, 400
        
        # Check if the username is already taken
        if User.query.filter_by(username=username).first():
            return {'message': 'Username already taken'}, 400
        
        # Hash the password before saving it in the database for security
        hashed_password = generate_password_hash(password)
        
        # Create a new user object with the hashed password
        new_user = User(username=username, password=hashed_password)

        # Add the new user to the session and commit the transaction to save in the database
        db.session.add(new_user)
        db.session.commit()

        # Return a success message if the user is created successfully
        return {'message':'User created successfully'}, 200
    
class UserLogin(Resource):
    def post(self):

        # Retrieve JSON data from the request body
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Fetch the user from the database by username
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and if the provided password matches the stored hash
        if user and check_password_hash(user.password, password):
            # Generate JWT token upon successful login
            access_token = create_access_token(identity=str(user.id))

            # Return the access token and the URL to redirect after login
            return {
                'access_token': access_token,
                'redirect_url': url_for('index', _external=True)
            }
        
        # Return an error message if the credentials are invalid
        return {'message': 'Invalid credentials'}, 401
    
class ProtectedResource(Resource):
    @jwt_required()
    def get(self):

        # Fetch the current user ID from the JWT token
        current_user_id = get_jwt_identity()

        # Return a message indicating the user accessed a protected resource
        return {'message': 'hello user, you accessed the protected resource'}
    
api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(ProtectedResource, '/secure')

tasks = []

@app.route("/")
def login():
    return render_template("login.html")

@app.route("/register_page", methods=["GET"])
def register_page():
    return render_template("register.html")

@app.route("/index")
def index():
    return render_template("index.html", tasks=tasks)

@app.route("/add", methods=["POST"])
def add():
    # Adds a new task from the form to the tasks list and redirects to the index page
    task = request.form['task']
    tasks.append({"task": task, "done": False})
    return redirect(url_for("index"))

@app.route("/edit/<int:index>", methods=["GET", "POST"])
def edit(index):
    # Edits an existing task
    # - For GET: Renders the edit page with the current task details.
    # - For POST: Updates the task with new data and redirects to the index page.
    task = tasks[index]
    if request.method == "POST":
        task['task'] = request.form["task"]
        return redirect(url_for("index"))
    else:
        return render_template("edit.html", task=task, index=index)
    
@app.route("/check/<int:index>")
def check(index):
    # Toggles the completion status of a task
    tasks[index]['done'] = not tasks[index]['done']
    return redirect(url_for("index"))

@app.route("/delete/<int:index>")
def delete(index):
    # Deletes a task from the tasks list
    del tasks[index]
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
def logout():
    # Logout
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)