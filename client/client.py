import os.path
from flask import Flask, render_template, send_from_directory, request, Response
from flask_cors import CORS
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding

from werkzeug.utils import secure_filename
import json
import base64

from encrypt_file import encrypt_file as rsa_encrypt
from encrypt_file import aes_encrypt, rsa_decrypt, aes_decrypt, get_private_key,get_public_key

app = Flask(__name__)
CORS(app)
downloads = os.path.join(app.root_path, 'downloads')
resources = os.path.join(app.root_path, 'keys')
static = os.path.join(app.root_path, 'static')

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/static/<path:filename>/")
def get_images(filename):
    return send_from_directory(static, filename)

@app.route("/download/", methods=["POST"])
def download():

    response = requests.post('http://127.0.0.1:5000/publickey')
    server_public_key = base64.b64decode(response.content)
    server_public_key = serialization.load_pem_public_key(
        server_public_key,
        backend=default_backend()
    )

    filename = request.form["filename"]
    username = request.headers["username"]
    username = base64.b64encode(rsa_encrypt(str.encode(username), server_public_key))
    filename = base64.b64encode(rsa_encrypt(str.encode(filename), server_public_key))

    response = requests.post('http://127.0.0.1:5000/download/',
                                data={"publickey":base64.b64encode(open("./keys/rsa_public_key.pem", "rb").read()),"filename":filename}, 
                                auth=(username,"")
                            )
    if response.status_code == 404:
        return Response(404)
    response_file_data = base64.b64decode(response.content)
    iv = response_file_data[:16]
    enc_file = response_file_data[16:]
    aes_decoded = rsa_decrypt(base64.b64decode(response.headers["aes"]), get_private_key())
    decoded_unpadded = aes_decrypt(aes_decoded, iv, enc_file)

    file_directory_name= os.path.join(downloads, request.form["filename"])
    with open(file_directory_name, "wb") as f:
                f.write(decoded_unpadded)
                f.close()
    return Response("File downloaded successfully.",200)

@app.route("/upload/", methods=["POST"])
def upload():
    username = request.headers["username"]
    response = requests.post('http://127.0.0.1:5000/publickey')
    server_public_key = base64.b64decode(response.content)
    server_public_key = serialization.load_pem_public_key(
            server_public_key,
            backend=default_backend()
        )

    if "file" in request.files:
        file = request.files['file']
        if file.filename != "":
            filename = secure_filename(file.filename)
            unencrypted_file = file.read()
            aes_key = open("./keys/aes_key.pem", "rb").read()

            iv = os.urandom(16)
            ct = aes_encrypt(iv, aes_key, unencrypted_file)
            encrypted_aes_key = rsa_encrypt(aes_key, server_public_key)
            encrypted_iv = rsa_encrypt(iv, server_public_key)

            file = {"file":(filename, ct)}
            username = base64.b64encode(rsa_encrypt(str.encode(username), server_public_key))
            headers ={}
            response = requests.post('http://127.0.0.1:5000/upload/', headers=headers, files=file, data={"aes":base64.b64encode(encrypted_aes_key), "iv":base64.b64encode(encrypted_iv)}, auth=(username,""))
            if response == 403:
                return Response("Disallowed Action",403)
            return Response("Uploaded Successfully", 200)


@app.route("/remove/", methods=["POST"])
def remove_files():
    response = requests.post('http://127.0.0.1:5000/publickey')
    server_public_key = base64.b64decode(response.content)
    server_public_key = serialization.load_pem_public_key(
        server_public_key,
        backend=default_backend()
    )

    filename = request.form["filename"]
    username = request.headers["username"]
    username = base64.b64encode(rsa_encrypt(str.encode(username), server_public_key))
    filename = base64.b64encode(rsa_encrypt(str.encode(filename), server_public_key))
    response = requests.post('http://127.0.0.1:5000/remove', data={"filename":filename}, auth=(username,""))
    if response.status_code == 200:
        return Response("Successfully removed", 200)

@app.route("/downloads/<path:filename>/")
def download_files_to_computer(filename):
    return send_from_directory(downloads, filename)

def new_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('./keys/rsa_private_key.pem', 'wb') as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('./keys/rsa_public_key.pem', 'wb') as f:
        f.write(public_pem)  

    aes_key = os.urandom(32)
    with open('./keys/aes_key.pem', 'wb') as f:
         f.write(aes_key)

if __name__ == "__main__":
    new_keys() 
    app.run(host="localhost",port=5001)