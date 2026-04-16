import socket
import threading
import json
from rsa_utils import generate_keys, pack_message, unpack_message


class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_public_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # rsa 1024 bit because otherwise it's slow
        self.public_key, self.private_key = generate_keys(1024)
        print("[server] RSA keys generated (1024-bit)")
        print(f"[server] listening on {self.host}:{self.port}")

        while True:
            c, addr = self.s.accept()
            username = c.recv(4096).decode()
            print(f"{username} tries to connect")

            # exchange public keys
            server_pub_json = json.dumps({"e": self.public_key[0], "n": self.public_key[1]})
            c.send(server_pub_json.encode())

            client_pub_json = c.recv(4096).decode()
            cpk = json.loads(client_pub_json)
            client_pub = (cpk["e"], cpk["n"])
            self.client_public_keys[c] = client_pub
            print(f"[server] key exchange done with {username}")

            self.broadcast(f'new person has joined: {username}', exclude=c)
            self.username_lookup[c] = username
            self.clients.append(c)

            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def broadcast(self, msg: str, exclude=None):
        """Encrypt and send msg to every connected client (except exclude)."""
        for client in self.clients:
            if client == exclude:
                continue
            try:
                pub = self.client_public_keys.get(client)
                if pub:
                    encrypted = pack_message(msg, pub)
                    client.send((encrypted + "\n").encode())
                else:
                    client.send((msg + "\n").encode())
            except Exception:
                pass

    def handle_client(self, c: socket, addr):
        buffer = ""
        while True:
            try:
                data = c.recv(8192)
                if not data:
                    break
                buffer += data.decode()

                while '\n' in buffer:
                    raw_str, buffer = buffer.split('\n', 1)
                    if not raw_str:
                        continue

                    # decrypt with server private key
                    plaintext = unpack_message(raw_str, self.private_key)
                    username = self.username_lookup.get(c, "unknown")
                    full_msg = f"{username}: {plaintext}"
                    print(full_msg)

                    self.broadcast(full_msg, exclude=c)
            except Exception as e:
                print(f"[server] error: {e}")
                break

        if c in self.clients:
            self.clients.remove(c)
        username = self.username_lookup.pop(c, "unknown")
        self.client_public_keys.pop(c, None)
        self.broadcast(f"{username} has left the chat")
        c.close()


if __name__ == "__main__":
    s = Server(9001)
    s.start()
