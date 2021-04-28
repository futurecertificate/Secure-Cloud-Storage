import os.path
from flask import Flask, render_template, send_from_directory, request, Response, jsonify
from flask_cors import CORS

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding

from encrypt_file import encrypt_file as rsa_encrypt
from encrypt_file import aes_encrypt, aes_decrypt, rsa_decrypt, get_private_key, get_public_key
from werkzeug.utils import secure_filename
import json
import base64


app = Flask(__name__)
CORS(app)
storage = os.path.join(app.root_path, 'storage')
resources = os.path.join(app.root_path, 'resources')
static = os.path.join(app.root_path, 'static')

MGMT_NAME = "CRAIG_WRIGHT"

@app.route("/")
def index():
    return render_template("main.html")

@app.route("/static/<path:filename>/")
def get_images(filename):
    return send_from_directory(static, filename)

@app.route("/password", methods=['POST'])
def get_cred():
    f = json.load(open("./resources/ip_access.json"))
    if request.remote_addr not in f:
        f[request.remote_addr] = 0
        with open("./resources/ip_access.json", "w") as ip_file:
            json.dump(f, ip_file)
    else:
        f[request.remote_addr] = f[request.remote_addr] + 1
        with open("./resources/ip_access.json", "w") as ip_file:
            json.dump(f, ip_file)
        if f[request.remote_addr] >= 100:
            return Response("Unauthorized. - Accesses exhausted for address.", 403)
    username = base64.b64decode(request.authorization["username"])
    username = rsa_decrypt(username, get_private_key()).decode()
    if username not in json.load(open("./resources/secure_cloud_storage_group.json", "rb"))["Users"]:
        return Response("Unauthorized. - User does not belong to remote access group.", 403)
    else:
        return Response("",200)


@app.route('/upload/', methods=['POST'])
def upload_file():

    # if user is in users.json os.join send 200
    # else send 403 forbidden

    with open('resources/secure_cloud_storage_group.json') as f:
            users = json.load(f)

    username = base64.b64decode(request.authorization["username"])
    username = rsa_decrypt(username, get_private_key()).decode()
    if username not in users["Users"]:
        return Response("", 403)

    if "file" in request.files:
        file = request.files['file']
        if file.filename != "":
            # decrypt aes key
            encrypted_aes_key = base64.b64decode(request.form["aes"])
            encrypted_iv = base64.b64decode(request.form["iv"])

            private_key = get_private_key()
            aes_key = rsa_decrypt(encrypted_aes_key, private_key)
            iv = rsa_decrypt(encrypted_iv, private_key)

            filename = secure_filename(file.filename)

            # decrypt received file using user's AES key
            ct = file.read()
            decoded_unpadded_file = aes_decrypt(aes_key,iv,ct)
            
            iv = os.urandom(16) # SAVE THIS SOMEWHERE
            
            with open("./keys/aes_key.pem", "rb") as key_file:
                local_aes = key_file.read()
                encrypted_file_with_aes = aes_encrypt(iv, local_aes, decoded_unpadded_file)

            # encode encrypted with base64 with iv
            base64_encoded_encrypted_file = base64.b64encode(iv + encrypted_file_with_aes)

            file_directory_name = os.path.join(storage, filename)
            with open(file_directory_name, "wb") as f:
                f.write(base64_encoded_encrypted_file)
                f.close()

            files = json.load(open("resources/files.json", "rb"))
            if filename not in files: 
                files.append(filename)

            with open("resources/files.json", "w") as f:
                json.dump(files, f)

            return Response('Successful Upload. ',200)

    return Response('', 204)


@app.route("/download/", methods=['POST'])
def download_file():
    
    # if user is in users.json, check if user has sent public key    
    # decrypt file and encrypt with users public key, then send
    # else send 403 forbidden

    with open('resources/secure_cloud_storage_group.json') as f:
            users = json.load(f)
    username = base64.b64decode(request.authorization["username"])
    username = rsa_decrypt(username, get_private_key()).decode()

    if username not in users["Users"]:
        return Response("Disallowed Action. ", 403)

    if "publickey" in request.form:
        user_public_key = base64.b64decode(request.form["publickey"])
        
        if "filename" in request.form:
            # encrypt aes key with user's public key
            # send encrypted file and encrypted aes key, encrypted IV back to user
            filename = base64.b64decode(request.form["filename"])
            filename = rsa_decrypt(filename, get_private_key()).decode()
            files = json.load(open("./resources/files.json","r"))
            if filename not in files:
                return("File not found. ", 404)
            
            public_key = serialization.load_pem_public_key(
                user_public_key,
                backend=default_backend()
            )

            encrypted_aes = rsa_encrypt(open("./keys/aes_key.pem", "rb").read(), public_key)

            response = send_from_directory(storage, filename)
            response.headers["aes"] = base64.b64encode(encrypted_aes)
            return response
            
    return Response('',204)

@app.route("/files/", methods=["POST"])
def serve_file_list():
    with open('resources/secure_cloud_storage_group.json') as f:
            users = json.load(f)

    if request.headers["username"] not in users["Users"]:
        return Response("Disallowed Action. ", 403)
    elif request.headers["username"] in users["Users"]:
        with open('resources/files.json') as f:
            files = json.load(f)
            print("Files returned.", files)
            return json.dumps(files)

@app.route('/remove/', methods=['POST'])
def remove_file():

    with open('resources/secure_cloud_storage_group.json') as f:
        users = json.load(f)
    
    username = base64.b64decode(request.authorization["username"])
    username = rsa_decrypt(username, get_private_key()).decode()

    if username not in users["Users"]:
        print("Not found")
        return Response("Disallowed Action", 403)
        

    with open('resources/files.json') as f:
        files = json.load(f)
        if "filename" in request.form:
            filename = base64.b64decode(request.form["filename"])
            filename = rsa_decrypt(filename, get_private_key()).decode()
            if filename in files:
                files.remove(filename)
                os.remove(storage +"/"+ filename)
                json.dump(files, open("resources/files.json","w"))
                return Response('Successfully removed file.',200)
        return Response('Invalid filename.', 404)

    
    return('',204)

@app.route('/users/', methods=['POST'])
def user_mgmt():

    # if sender is server mgmt then read contents of request and act accordingly
    print(request.form)
    request_data = request.form

    if request_data["username"] == MGMT_NAME:
        with open('resources/secure_cloud_storage_group.json') as f:
            users = json.load(f)
        
        if request_data["add_user"] not in users["Users"]:
            users["Users"].append(request_data["add_user"])
            
            try:
                with open('resources/secure_cloud_storage_group.json', "wb") as f:
                    json.dump(users, f)
            except Exception:
                print("Something broke while writing to users.json.")
            return('User Successfully Added. ',200)
        return('User Already Exists. ',200)
    else:
        return('Disallowed Action. ', 403)
    return('',204)

@app.route('/publickey/', methods=['POST'])
def give_group_member_public_key():

    return base64.b64encode(open("./keys/rsa_public_key.pem", "rb").read())

# this might take time when called
@app.route('/privatekey/', methods=['POST'])
def create_new_private_key():

    # check if server mgmt
    # create new private key
    # decrypt files and encrypt with new private key one by one
    # store new private key in pk.json
    

    return('',204)

def auto_create_private_key():
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
        # auto_create_private_key() # uncomment to automatically create new public and private keys on starting server
        ip_accesses = {}
        f = open("./resources/ip_access.json", "w")
        json.dump(ip_accesses, f)
        f.close()
        app.run() 