'''
Com o python e pip instalados, instale os seguintes modulos:
pip install cryptography
pip install pycryptodome

Execute o prompt no terminal aberto com o diretório do arquivo:
py "envolope assinado.py"

'''

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from Cryptodome.Cipher import ARC4, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import os

def generate_rsa_keys():
    # Geração da chave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Salvar a chave privada no formato PEM
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Geração da chave pública a partir da chave privada
    public_key = private_key.public_key()

    # Salvar a chave pública no formato PEM
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes( 
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def create_signed_envelope_AES(message, private_key_path, public_key_path, symmetric_key_size=32):
    try:
        # Carregar chaves RSA
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # Gerar chave simétrica aleatória
        symmetric_key = os.urandom(symmetric_key_size)

        # Gerar um IV aleatório
        iv = os.urandom(16)

        # Cifrar a mensagem com a chave simétrica
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()

        # Assinar a mensagem cifrada com a chave privada do remetente
        signature = private_key.sign(
            ct,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Cifrar a chave simétrica com a chave pública do destinatário
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Chave simétrica criptografada: ", encrypted_symmetric_key)
        print("Texto cifrado: ", ct)
        print("Assinatura: ", signature)

        return encrypted_symmetric_key, ct, signature, iv
    except Exception as e:
        print(f"Erro ao criar o envelope assinado: {str(e)}")

def open_signed_envelope_AES(encrypted_symmetric_key, ct, signature, iv, private_key_path, public_key_path):
    try:
        # Carregar chaves RSA
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # Decifrar a chave simétrica com a chave privada do destinatário
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
       
        # Teste se a chave é incorreta com a linha abaixo: 
        # signature = signature[5:10] 
        # Verificar a assinatura da mensagem cifrada com a chave pública do remetente
        public_key.verify(
            signature,
            ct,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Chaves coincidem")
        # Decifrar a mensagem com a chave simétrica
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        print("Dados decifrados: ", data.decode('utf-8'))

        return data
    except Exception as e:
        print(f"Erro ao abrir o envelope assinado: {str(e)}")

# Algoritmo DES



def create_signed_envelope_3DES(message, private_key_path, public_key_path):
    try:
        # Carregar chaves RSA
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # Gerar chave simétrica aleatória
        symmetric_key = os.urandom(24)

        # Gerar um IV aleatório
        iv = os.urandom(8)

        # Cifrar a mensagem com a chave simétrica
        cipher = Cipher(algorithms.TripleDES(symmetric_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(64).padder()
        padded_data = padder.update(message) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()

        print("Texto cifrado: ", ct)

        # Assinar a mensagem cifrada com a chave privada do remetente
        signature = private_key.sign(
            ct,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Assinatura: ", signature)

        # Cifrar a chave simétrica com a chave pública do destinatário
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("Chave simétrica criptografada: ", encrypted_symmetric_key)

        return encrypted_symmetric_key, ct, signature, iv
    except Exception as e:
        print(f"Erro ao criar o envelope assinado: {str(e)}")

def open_signed_envelope_3DES(encrypted_symmetric_key, ct, signature, iv, private_key_path, public_key_path):
    try:
        # Carregar chaves RSA
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # Decifrar a chave simétrica com a chave privada do destinatário
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Verificar a assinatura da mensagem cifrada com a chave pública do remetente
        public_key.verify(
            signature,
            ct,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Chaves coincidem")

        # Decifrar a mensagem com a chave simétrica
        cipher = Cipher(algorithms.TripleDES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(64).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        print("Dados decifrados: ", data.decode('utf-8'))

        return data
    except Exception as e:
        print(f"Erro ao abrir o envelope assinado: {str(e)}")

def create_signed_envelope_RC4(message, private_key_path, public_key_path, symmetric_key_size=32):
    try:
        # Carregar chaves RSA
        with open(private_key_path, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())
        with open(public_key_path, "rb") as key_file:
            public_key = RSA.import_key(key_file.read())
        if isinstance(message, str):
            message = message.encode('utf-8')
        # Gerar chave simétrica aleatória
        symmetric_key = get_random_bytes(symmetric_key_size)
        print("Chave simétrica gerada.", symmetric_key)
        
        # Criptografar a mensagem com a chave simétrica
        cipher = ARC4.new(symmetric_key)
        ct = cipher.encrypt(message)
        print("Mensagem criptografada com chave simétrica.", ct)
        
        # Assinar a mensagem criptografada com a chave privada do remetente
        h = SHA256.new(ct)
        signature = pkcs1_15.new(private_key).sign(h)
        print("Mensagem assinada com chave privada.", signature)
        
        # Criptografar a chave simétrica com a chave pública do destinatário
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)
        print("Chave simétrica criptografada com chave pública.",encrypted_symmetric_key)
        
        return encrypted_symmetric_key, ct, signature
    except Exception as e:
        print(f"Erro ao criar envelope assinado: {str(e)}")

def open_signed_envelope_RC4(encrypted_symmetric_key, ct, signature, private_key_path, public_key_path):
    try:
        # Carregar chaves RSA
        with open(private_key_path, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())
        with open(public_key_path, "rb") as key_file:
            public_key = RSA.import_key(key_file.read())
        
        # Descriptografar a chave simétrica com a chave privada do destinatário
        cipher_rsa = PKCS1_OAEP.new(private_key)
        symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)
        print("Chave simétrica descriptografada com chave privada.", symmetric_key)
        
        # Verificar a assinatura da mensagem criptografada com a chave pública do remetente
        h = SHA256.new(ct)
        pkcs1_15.new(public_key).verify(h, signature)
        print("Assinatura verificada com chave pública.")
        
        # Descriptografar a mensagem com a chave simétrica
        cipher = ARC4.new(symmetric_key)
        data = cipher.decrypt(ct)
        print("Mensagem descriptografada com chave simétrica.", data)
        
        return data.decode('utf-8')
   
    except Exception as e:
        print(f"Erro ao abrir envelope assinado: {str(e)}")

# Gere um par de chaves RSA
generate_rsa_keys()

# Crie um envelope assinado
message = b"Sua mensagem aqui"

#Escolha um algoritmo de cifragem
'''
Opção 
1 == AES
2 == DES
3 == RC4
'''       

while 1 :
    # Quando o compilador do vscode sinalizar 'ValueError" retire o coloque um espaço na string dentro da função input
    opcao = int(input("Selecione uma opção:\n 1 == AES \n 2 == DES \n 3 == RC4 \n "))

    if opcao == 1 :

        encrypted_symmetric_key, ct, signature, iv = create_signed_envelope_AES(message, "private_key.pem", "public_key.pem")

        # Abra o envelope assinado
        data = open_signed_envelope_AES(encrypted_symmetric_key, ct, signature, iv, "private_key.pem", "public_key.pem")

    if opcao == 2 :

        encrypted_symmetric_key, ct, signature, iv = create_signed_envelope_3DES(message, "private_key.pem", "public_key.pem")
        # Abra o envelope assinado
        data = open_signed_envelope_3DES(encrypted_symmetric_key, ct, signature, iv, "private_key.pem", "public_key.pem")

    if opcao == 3 :
        encrypted_symmetric_key, ct, signature = create_signed_envelope_RC4(message, "private_key.pem", "public_key.pem")

        # Abra o envelope assinado
        data = open_signed_envelope_RC4(encrypted_symmetric_key, ct, signature, "private_key.pem", "public_key.pem")
