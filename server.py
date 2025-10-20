import socket
import threading
import json
import time

class ChatServer:
    def __init__(self, host='localhost', port=5000): 
        self.host = host
        self.port = port
        self.clients = {}  
        self.server_socket = None

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        print(f"Server started on {self.host}:{self.port}")
        print("Waiting for the client to connect!")

        while True:
            conn, addr = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()

    def handle_client(self, conn, addr):
        client_id = None

        try:
            while True:
                data = conn.recv(4096).decode('utf-8')
                if not data:
                    break

                message = json.loads(data)
                print(f"Message received from {addr}: {message['type']}")

                if message['type'] == 'register':
                    client_id = message['client_id']
                    self.clients[client_id] = {
                        'conn': conn,
                        'public_key': message['public_key']
                    }
                    print(f"Registered client id: {client_id}")
                    print(f"Available client name: {list(self.clients.keys())}")

                elif message['type'] == 'get_public_key':
                    target_client = message['target_client']
                    if target_client in self.clients:
                        response = {
                            'type': 'public_key_response',
                            'target_client': target_client,
                            'public_key': self.clients[target_client]['public_key']
                        }
                        conn.send(json.dumps(response).encode('utf-8'))
                        print(f"Sent the public key of {target_client} to {message['client_id']}")
                    else:
                        error_msg = {
                            'type': 'error',
                            'message': f'Client {target_client} not found'
                        }
                        conn.send(json.dumps(error_msg).encode('utf-8'))

                elif message['type'] == 'session_key':
                    recipient = message['recipient']
                    if recipient in self.clients:
                        forward_msg = {
                            'type': 'session_key',
                            'sender': message['sender'],
                            'encrypted_session_key': message['encrypted_session_key']
                        }
                        self.clients[recipient]['conn'].send(
                            json.dumps(forward_msg).encode('utf-8')
                        )
                        print(f"Forwarded session key from {message['sender']} to {recipient}")
                    else:
                        print(f"Recipient {recipient} not found")
                elif message['type'] == 'send_message':
                    recipient = message['recipient']
                    if recipient in self.clients:
                        forward_msg = {
                            'type': 'message',
                            'sender': message['sender'],
                            'ciphertext': message['ciphertext'],
                            'timestamp': time.time()
                        }
                        self.clients[recipient]['conn'].send(
                            json.dumps(forward_msg).encode('utf-8')
                        )
                        print(f"Message forwarded from {message['sender']} to {recipient}")
                    else:
                        print(f"Recipient {recipient} not found")

        except Exception as e:
            print(f"Error with client {addr}: {e}")
        finally:
            if client_id and client_id in self.clients:
                del self.clients[client_id]
                print(f"Client {client_id} disconnected")
            conn.close()


if __name__ == "__main__":
    server = ChatServer()
    server.start_server()