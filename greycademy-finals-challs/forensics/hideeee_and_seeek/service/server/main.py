from flask import Flask
app = Flask(__name__)

@app.route("/bleh")
def hello_world():
    return "grey{1nJeCtinG_iNtO_fUnE3_pR0ce55}"

if __name__  == "__main__":
    app.run("0.0.0.0", 32000)
