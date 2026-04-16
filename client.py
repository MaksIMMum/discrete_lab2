import socket
import threading
import json
from rsa_utils import generate_keys, pack_message, unpack_message


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        self.public_key, self.private_key = generate_keys(1024)
        print("[client] RSA keys generated (1024-bit)")

        # exchange public keys
        server_pub_json = self.s.recv(4096).decode()
        serv_p_k = json.loads(server_pub_json)
        self.server_public_key = (serv_p_k["e"], serv_p_k["n"])

        # send own public key to server
        client_pub_json = json.dumps({"e": self.public_key[0], "n": self.public_key[1]})
        self.s.send(client_pub_json.encode())
        print("[client] key exchange complete")

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        buffer = ""
        while True:
            try:
                data = self.s.recv(8192)
                if not data:
                    print("[client] disconnected from server")
                    break
                buffer += data.decode()

                while '\n' in buffer:
                    raw_str, buffer = buffer.split('\n', 1)
                    if not raw_str:
                        continue

                    # decrypt with private key and verify signature with server public key
                    text = unpack_message(raw_str, self.private_key, self.server_public_key)
                    print(text)
            except ValueError as e:
                print(f"[client] integrity error: {e}")
            except Exception as e:
                print(f"[client] error: {e}")
                break

    def write_handler(self):
        while True:
            message = input()
            
            # encrypt with server public key and sign with own private key
            encrypted = pack_message(message, self.server_public_key, self.private_key)
            self.s.send((encrypted + "\n").encode())


if __name__ == "__main__":
    username = input("Enter your username: ")
    cl = Client("127.0.0.1", 9001, username)
    cl.init_connection()
