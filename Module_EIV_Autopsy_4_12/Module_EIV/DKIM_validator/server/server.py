import requests
from flask import Flask,request,render_template
from flask_cors import CORS
app = Flask(__name__)
CORS(app)

@app.route("/",methods=['GET'])
def index():
   return render_template('./index.html')

@app.route("/output.json",methods=['GET'])
def json():
   return render_template('./output.json')

if __name__=="__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-i', '--ip', default='127.0.0.1', type=str, help='ip to listen on')
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    
    host = args.ip
    port = args.port

    app.run(host=host, port=port)


