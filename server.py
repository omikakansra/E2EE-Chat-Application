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
        print("Waiting for clients to connect...\n")

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
                msg_type = message.get('type', 'unknown')

                if msg_type == 'register':
                    client_id = message['client_id']
                    self.clients[client_id] = {
                        'conn': conn,
                        'public_key': message['public_key']
                    }
                    print(f"[REGISTER] {client_id} connected.")
                    print(f"Active clients: {list(self.clients.keys())}\n")

                elif msg_type == 'get_public_key':
                    target = message['target_client']
                    if target in self.clients:
                        response = {
                            'type': 'public_key_response',
                            'target_client': target,
                            'public_key': self.clients[target]['public_key']
                        }
                        conn.send(json.dumps(response).encode('utf-8'))
                        print(f"[KEY REQUEST] Sent {target}'s public key to {message['client_id']}\n")
                    else:
                        error_msg = {'type': 'error', 'message': f'Client {target} not found'}
                        conn.send(json.dumps(error_msg).encode('utf-8'))

                elif msg_type == 'session_key':
                    recipient = message['recipient']
                    if recipient in self.clients:
                        forward_msg = {
                            'type': 'session_key',
                            'sender': message['sender'],
                            'encrypted_session_key': message['encrypted_session_key']
                        }
                        self.clients[recipient]['conn'].send(json.dumps(forward_msg).encode('utf-8'))
                        print(f"[SESSION KEY] Forwarded from {message['sender']} → {recipient}\n")
                    else:
                        print(f"[ERROR] Recipient {recipient} not found.\n")

                elif msg_type == 'send_message':
                    recipient = message['recipient']
                    if recipient in self.clients:
              
                        print(f"[ENCRYPTED MESSAGE] Received from {message['sender']}:")
                        print(f"Ciphertext: {message['ciphertext']}\n")

                        forward_msg = {
                            'type': 'message',
                            'sender': message['sender'],
                            'ciphertext': message['ciphertext'],
                            'timestamp': time.time()
                        }
                        self.clients[recipient]['conn'].send(json.dumps(forward_msg).encode('utf-8'))
                        print(f"[FORWARDED] Message sent to {recipient}\n")
                    else:
                        print(f"[ERROR] Recipient {recipient} not found.\n")

        except Exception as e:
            print(f"[ERROR] Client {addr}: {e}\n")
        finally:
            if client_id and client_id in self.clients:
                del self.clients[client_id]
                print(f"[DISCONNECTED] {client_id} removed.\n")
            conn.close()


if __name__ == "__main__":
    server = ChatServer()
    server.start_server()
