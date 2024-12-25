# Import flask module
from flask import Flask, request 
from flask_cors import CORS
import json
from clsPgDatabase import pgDatabase;


app = Flask(__name__)
app.config.update({
    'TESTING': True,
    'DEBUG': True,
})
CORS(app)


import auth;
app.register_blueprint(auth.bp)

 
@app.route('/')
def index():
    return '<H1>Under construction auth</H1>'


# main driver function
if __name__ == "__main__":
    app.run()


