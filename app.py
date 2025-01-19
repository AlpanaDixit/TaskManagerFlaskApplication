from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__, template_folder="templates")

tasks = [{"task": "Sample Task", "done" : False}]

@app.route("/")
def index():
    return render_template("index.html", tasks=tasks)

@app.route("/add", methods = ["POST"])
def add():
    # Adds a new task from the form to the tasks list and redirects to the index page
    task = request.form['task']
    tasks.append({"task": task, "done": False})
    return redirect(url_for("index"))

@app.route("/edit/<int:index>", method=["GET", "POST"])
def edit(index):
    # Edits an existing task
    # - For GET: Renders the edit page with the current task details.
    # - For POST: Updates the task with new data and redirects to the index page.
    task = tasks[index]
    if request.method == "POST":
        task['task'] = request.form["todo"]
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