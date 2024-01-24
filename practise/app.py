from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("/index.html")

@app.route("/second", methods=["POST"])
def second():
    x = request.form.get('x')
    return render_template("/second.html", x=x)