import asyncio
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from getpass import getpass

class Bot:
    def __init__(self, username, password):
        self.username = username
        self.password = self.generate_password(password)    
        self.loggedIn = False
    
    async def login(self):
        reader, writer = await asyncio.open_connection('live4.tos.blankmediagames.com', 3600)
        writer.write(b'\x02\x02\x02\x01' + b'13050' + b'\x1e' + self.username.encode() + b'\x1e' + self.password + b'\x00')
        await writer.drain()
        await self.listen(reader, writer)
    
    async def listen(self, reader, writer):
        while True:
            data = await reader.read(4096)
            print(data)
            if data == b'\xe2\x03\x00':
                if not self.loggedIn:
                    print("Invalid login.")
                else:
                    print("Disconnected.")

            elif data == b'\x01\x02\x00':
                print("Logged in.")
                self.loggedIn = True

    def generate_password(self, password):
        key = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAziIxzMIz7ZX4KG5317Sm\nVeCt9SYIe/+qL3hqP5NUX0i1iTmD7x9hFR8YoOHdAqdCJ3dxi3npkIsO6Eoz0l3e\nH7R99DX16vbnBCyvA3Hkb1B/0nBwOe6mCq73vBdRgfHU8TOF9KtUOx5CVqR50U7M\ntKqqc6M19OZXZuZSDlGLfiboY99YV2uH3dXysFhzexCZWpmA443eV5ismvj3Nyxv\nRk/4ushZV50vrDjYiInNEj4ICbTNXQULFs6Aahmt6qmibEC6bRl0S4TZRtzuk2a3\nTpinLJooDTt9s5BvRRh8DLFZWrkWojgrzS0sSNcNzPAXYFyTOYEovWWKW7TgUYfA\ndwIDAQAB'
        password = PKCS1_v1_5.new(RSA.importKey(b64decode(key))).encrypt(password.encode())
        return b64encode(password)

username = input("Username: ")
password = getpass("Password: ")

asyncio.run(Bot(username, password).login())
