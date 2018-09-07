#!/usr/bin/env python

import os

from flask import Flask, request, Response, render_template

from csr import CsrGenerator

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/security')
def security():
    return render_template('security.html')


@app.route('/generate', methods=['POST'])
def generate_csr():
    csr = CsrGenerator(request.form)
    response = '\n'.join([csr.csr, csr.private_key])
    return Response(response, mimetype='text/plain')


@app.route('/gen_spark_request')
def generate_spark_request():
    
    # Intention here is to get the CSR and submit a request into Spark.
    # We would then return the Spark REQ number to the user
    # NOTE: None of this is working - DO NOT USE
    
    apikey = 'insert-api-key'
    response = 'get spark response'

    return render_template('spark_req_number.html')



if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', 5555))
    app.run(host='0.0.0.0', port=port)
