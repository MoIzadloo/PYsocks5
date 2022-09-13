import asyncio
import struct
import hashlib
import socket

class Cryptography:
    @staticmethod
    def genHash(password):
        return hashlib.sha384(password).hexdigest()

    @staticmethod
    def verfyHash(secret, password):
        return hashlib.sha384(secret).hexdigest() == password

class ClientProtocol(asyncio.Protocol):
    def __init__(self, server):
        self.server = server

    def connection_made(self, transport):
        self.transport = transport
        addr, port = transport.get_extra_info("peername")
        self.server.write(struct.pack("!BBBB", 5, 0, 0, 1) + socket.inet_aton(addr) + struct.pack("!H", port))
        self.server.state = self.server.SOCKS_STATE_TUNNEL
        
    def data_received(self, data):
        print("Received data: ", data)
        self.server.write(data)

    def write(self, data):
        self.transport.write(data)

class ServerProtocol(asyncio.Protocol):
    SOCKS_STATE_CONNECTION_MADE = "0"
    SOCKS_STATE_NEGOTIATE = "1"
    SOCKS_STATE_TUNNEL = "2"
    SOCKS_VERSION = 5
    SOCKS_SUPPORTED_METHOD = 2
    SOCKS_USERNAME = "admin"
    SOCKS_PASSWORD = "7daf53674bd9bab01d8e0180494a3f08a56bece049c28251f6252bb27178aaa13e0f79c0ab9d3079d8801f5c4204cf93"

    def __init__(self):
        self.loop = asyncio.get_running_loop()

    def connection_made(self, transport):
        self.state = self.SOCKS_STATE_CONNECTION_MADE
        self.transport = transport
        print("New connection made :", transport.get_extra_info("peername"))
        self.reader = asyncio.StreamReader()
        self.reader.set_transport(transport)
        self.loop.create_task(self.negotiate())

    def data_received(self, data):
        if self.state == self.SOCKS_STATE_NEGOTIATE:
            print("Received NEGOTIATE data: ", data)
            self.reader.feed_data(data)
        elif self.state == self.SOCKS_STATE_TUNNEL:
            print("Received send: ", data)
            self.client.write(data)

    async def negotiate(self):
        self.state = self.SOCKS_STATE_NEGOTIATE
        v, nm = struct.unpack("!BB", await self.reader.readexactly(2))
        m = []
        for x in range(nm):
            m.append(ord(await self.reader.readexactly(1)))
        if self.SOCKS_SUPPORTED_METHOD in m:
            self.write(struct.pack("!BB", 5, 2))
        v, ul = struct.unpack("!BB", await self.reader.readexactly(2))
        username = (await self.reader.readexactly(ul)).decode("utf-8")
        pl = ord(await self.reader.readexactly(1))
        password = (await self.reader.readexactly(pl))
        if Cryptography.verfyHash(password, self.SOCKS_PASSWORD) and username == self.SOCKS_USERNAME:
            self.write(struct.pack("!BB", 1, 0))
            v, cmd, rsv, atyp = struct.unpack("!BBBB", await self.reader.readexactly(4))
            if cmd == 1:
                if atyp == 3:
                    dl = ord(await self.reader.readexactly(1))
                    domain = (await self.reader.readexactly(dl)).decode("utf-8")
                    port = struct.unpack("!H", await self.reader.readexactly(2))[0]
                    domain = socket.getaddrinfo(domain, port)[0][-1][0]
                    self.client = ClientProtocol(self)
                    await self.loop.create_connection(lambda: self.client, domain, port)
    
    def write(self, data):
        self.transport.write(data)

async def main():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(ServerProtocol, '0.0.0.0', 1080)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())