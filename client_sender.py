import socket
import json
import threading
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
import base64


class ClientSender:
    def __init__(self, client_id='alice', server_host='localhost', server_port=5000):
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.private_key = None
        self.public_key = None
        self.session_key = None
        self.fernet = None
        self.messages = []
        self.server_socket = None
        self.bob_public_key = None

        self.generate_keys()

    def generate_keys(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # Serialize public key for sending
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        print(f"Generated RSA keys for {self.client_id}")

    def connect_to_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.connect((self.server_host, self.server_port))

        # Register with server
        register_msg = {
            'type': 'register',
            'client_id': self.client_id,
            'public_key': self.public_key_pem
        }
        self.server_socket.send(json.dumps(register_msg).encode('utf-8'))
        print("Registered with server")

        # Start listening for responses
        listen_thread = threading.Thread(target=self.listen_for_responses)
        listen_thread.daemon = True
        listen_thread.start()

    def listen_for_responses(self):
        try:
            while True:
                data = self.server_socket.recv(4096).decode('utf-8')
                if not data:
                    break

                message = json.loads(data)
                if message['type'] == 'public_key_response':
                    # Store Bob's public key
                    bob_public_key_pem = message['public_key']
                    self.bob_public_key = serialization.load_pem_public_key(
                        bob_public_key_pem.encode('utf-8')
                    )
                    print("Received Bob's public key from the server")

        except Exception as e:
            print(f"Error in response listener: {e}")

    def get_bob_public_key(self):
        # Request Bob's public key from server
        request_msg = {
            'type': 'get_public_key',
            'client_id': self.client_id,
            'target_client': 'bob'
        }
        self.server_socket.send(json.dumps(request_msg).encode('utf-8'))
        print("Requesting Bob's public key from the server.")

        # Wait for the response
        max_wait = 10  # 10 seconds max
        start_time = time.time()
        while not self.bob_public_key and (time.time() - start_time) < max_wait:
            time.sleep(0.5)

        if self.bob_public_key:
            return True
        else:
            print("Failed to get Bob's public key")
            return False

    def start_session_with_bob(self):
        # Generate AES session key
        self.session_key = Fernet.generate_key()
        self.fernet = Fernet(self.session_key)
        print("Generated AES session key")

        # Get Bob's actual public key from server
        if not self.get_bob_public_key():
            print("Cannot establish session without Bob's public key")
            return False

        # Encrypt session key with Bob's REAL public key
        encrypted_session_key = self.bob_public_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Send encrypted session key to Bob via server
        session_msg = {
            'type': 'session_key',
            'sender': self.client_id,
            'recipient': 'bob',
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8')
        }
        self.server_socket.send(json.dumps(session_msg).encode('utf-8'))
        print("Sent encrypted session key to Bob")
        print("Session key exchange completed!")
        return True

    def send_message(self, message):
        if not self.fernet:
            print("No session key established.")
            return

        # Encrypt message with AES
        ciphertext = self.fernet.encrypt(message.encode('utf-8'))
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

        # Send to server
        msg = {
            'type': 'send_message',
            'sender': self.client_id,
            'recipient': 'bob',
            'ciphertext': ciphertext_b64
        }
        self.server_socket.send(json.dumps(msg).encode('utf-8'))

        # Log message
        self.log_message(message, ciphertext_b64)
        print(f"Sent the encrypted message: {message}")

    def log_message(self, plaintext, ciphertext):
        message_entry = {
            'plaintext': plaintext,
            'ciphertext': ciphertext,
            'sender': self.client_id,
            'timestamp': time.time()
        }
        self.messages.append(message_entry)

        # Save to JSON file
        with open(f'messages_{self.client_id}.json', 'w') as f:
            json.dump(self.messages, f, indent=2)

    def start_chat(self):
        self.connect_to_server()

        print("Waiting for Bob to register.")
        time.sleep(3)  # Wait for Bob to register

        print("Starting session key exchange with Bob.")
        if self.start_session_with_bob():
            print("\nYou are now Alice (Sender). Start typing messages:")
            print("Type 'quit' to exit\n")

            while True:
                message = input("Alice: ")
                if message.lower() == 'quit':
                    break
                self.send_message(message)
        else:
            print("Failed to establish secure session with Bob")

        print("Bye!")


if __name__ == "__main__":
    client = ClientSender('alice')
    client.start_chat()