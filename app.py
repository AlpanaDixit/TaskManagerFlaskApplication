from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from flask_jwt_extended import create_access_token, JWTManager

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
        data = request.get_json()
        username = data['username']
        password = data['password']

        if not username or not password:
            return {'message': 'Missing username or password'}, 400
        if User.query.filter_by(username=username).first():
            return {'message': 'Username already taken'}, 400
        
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return {'message':'User created successfully'}, 200
    
class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}
        
        return {'message': 'Invalid credentials'}, 401
    
api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')

tasks = []

@app.route("/")
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

if __name__ == '__main__':
    app.run(debug=True)