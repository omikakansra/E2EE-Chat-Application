import socket
import json
import threading
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
import base64


class ClientReceiver:
    def __init__(self, client_id='bob', server_host='localhost', server_port=5000):
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.private_key = None
        self.public_key = None
        self.session_key = None
        self.fernet = None
        self.messages = []
        self.server_socket = None
        self.running = True

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

        # Start listening for messages
        listen_thread = threading.Thread(target=self.listen_for_messages)
        listen_thread.daemon = True
        listen_thread.start()

    def listen_for_messages(self):
        try:
            while self.running:
                data = self.server_socket.recv(4096).decode('utf-8')
                if not data:
                    break

                message = json.loads(data)

                if message['type'] == 'session_key':
                    self.handle_session_key(message)
                elif message['type'] == 'message':
                    self.handle_message(message)

        except Exception as e:
            if self.running:  # Only print error if we're still running
                print(f"Error receiving messages: {e}")

    def handle_session_key(self, message):
        try:
            print(f"\nProcessing session key from {message['sender']}...")

            # Decrypt session key with Bob's private key
            encrypted_session_key = base64.b64decode(message['encrypted_session_key'])

            # Use Bob's actual private key to decrypt
            session_key = self.private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            self.session_key = session_key
            self.fernet = Fernet(session_key)
            print("SESSION KEY ESTABLISHED WITH ALICE!")
            print("Ready to receive encrypted messages.")

        except Exception as e:
            print(f"Error decrypting session key: {e}")

    def handle_message(self, message):
        ciphertext_b64 = message['ciphertext']
        sender = message['sender']

        print(f"\n" + "=" * 50)
        print(f"Received encrypted message from {sender}:")
        print(f"Ciphertext: {ciphertext_b64}")

        # Check if session key is established
        if not self.fernet:
            print("No session key established. Cannot decrypt message.")
            print("Make sure Alice sends the session key first!")
            return

        # Decrypt message
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = self.fernet.decrypt(ciphertext).decode('utf-8')

            print(f"Decrypted message: {plaintext}")
            print("=" * 50)

            # Log message
            self.log_message(plaintext, ciphertext_b64, sender)

        except Exception as e:
            print(f"Error decrypting message: {e}")

    def log_message(self, plaintext, ciphertext, sender):
        message_entry = {
            'plaintext': plaintext,
            'ciphertext': ciphertext,
            'sender': sender,
            'timestamp': time.time()
        }
        self.messages.append(message_entry)

        # Save to JSON file
        with open(f'messages_{self.client_id}.json', 'w') as f:
            json.dump(self.messages, f, indent=2)

    def start_receiving(self):
        self.connect_to_server()
        print(f"\n{self.client_id} is listening for messages.")
        print("Waiting for session key from Alice.")
        print("Type 'quit' and press Enter to exit\n")

        # Keep the main thread alive with proper input handling
        try:
            while self.running:
                user_input = input()
                if user_input.lower() == 'quit':
                    self.running = False
                    print("Bye!")
                    break
                else:
                    print("Type 'quit' to exit")
        except KeyboardInterrupt:
            self.running = False
            print("\nBye!")


if __name__ == "__main__":
    client = ClientReceiver('bob')
    client.start_receiving()