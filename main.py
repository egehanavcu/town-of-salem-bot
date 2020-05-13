import asyncio
import re
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from getpass import getpass

class Bot:
    def __init__(self, username, password):
        self.username = username
        self.password = self.generate_password(password)    
        self.loggedIn = False

        self.reader = None
        self.writer = None

    async def login(self):
        self.reader, self.writer = await asyncio.open_connection('live4.tos.blankmediagames.com', 3600)
        await self.send_packet(b'\x02\x02\x02\x01' + b'13050' + b'\x1e' + self.username.encode() + b'\x1e' + self.password + b'\x00') # 13050 is something like version.
        await self.listen()
    
    async def listen(self):
        while True:
            data = await self.reader.read(4096)
            dataDecode = data.decode("utf-8", errors="ignore")
            print(data)

            if data == b'\xe2\x03\x00':
                if not self.loggedIn:
                    print("Invalid login.")
                else:
                    print("Disconnected.")

            elif data == b'\x01\x02\x00':
                print("Logged in.")
                self.loggedIn = True
                await self.send_packet(b'K\x00') # This packet is sent after login; I don't know what it does: 'K\x00'

            elif b'\xee\x01\x01You are already in a party. Failed to create new party.\x00' in data:
                print("Already in party.")

            elif data.startswith(b'#') and data.endswith(b'\x00'):
                messageInfo = dataDecode[1:-1].split('*', 1)
                if len(messageInfo) == 2:
                    username, message = messageInfo
                    print("[Lobby] [%s] %s" % (username, message))

            # Creating new party packet (send): \x1f\x01\x00
            # Creating new party packet (receive): \x1d\x01\x00

            # Lobby sending message packet (send): $message\x00
            # Lobby sending message packet (receive): #username*message\x00

    async def send_packet(self, packet):
        self.writer.write(packet)
        await self.writer.drain()

    async def send_lobby_message(self, message):
        await self.send_packet(b'$%s\x00' % message.encode("utf-8"))

    def generate_password(self, password):
        key = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAziIxzMIz7ZX4KG5317Sm\nVeCt9SYIe/+qL3hqP5NUX0i1iTmD7x9hFR8YoOHdAqdCJ3dxi3npkIsO6Eoz0l3e\nH7R99DX16vbnBCyvA3Hkb1B/0nBwOe6mCq73vBdRgfHU8TOF9KtUOx5CVqR50U7M\ntKqqc6M19OZXZuZSDlGLfiboY99YV2uH3dXysFhzexCZWpmA443eV5ismvj3Nyxv\nRk/4ushZV50vrDjYiInNEj4ICbTNXQULFs6Aahmt6qmibEC6bRl0S4TZRtzuk2a3\nTpinLJooDTt9s5BvRRh8DLFZWrkWojgrzS0sSNcNzPAXYFyTOYEovWWKW7TgUYfA\ndwIDAQAB'
        password = PKCS1_v1_5.new(RSA.importKey(b64decode(key))).encrypt(password.encode())
        return b64encode(password)

username = input("Username: ")
password = getpass("Password: ")

asyncio.run(Bot(username, password).login())
