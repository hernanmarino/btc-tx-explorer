import asyncio
import json
import random
import socket
import ssl
from helpers import address_to_scripthash

class ElectrumXClient:
    # List of known public servers (you can add more)
    PUBLIC_SERVERS = [
        ("electrum.blockstream.info", 50002, True),  # (host, port, is_ssl)
        ("electrum.bitaroo.net", 50002, True),
        # ("electrum.hodlister.co", 50002, True),    # Not good results
        #("electrum3.hodlister.co", 50002, True),    # Not good results
        ("bitcoin.lukechilds.co", 50002, True),
        ("electrum.emzy.de", 50002, True),          # Maintained by trusted community member Emzy
        ("electrum.nixbitcoin.org", 50002, True),   # Maintained by nixbitcoin project
        ("electrum.blockstream.de", 50002, True),   # Blockstream's German server
        ("fortress.qtornado.com", 50002, True),     # Maintained by Fountain/NYDIG
        ("electrum.acinq.co", 50002, True),         # Maintained by ACINQ (Lightning Network company)
        ("electrum.coinext.com.br", 50002, True),   # Large Brazilian exchange
        ("electrum.petrkr.net", 50002, True),       # Long-running community server
        ("e.keff.org", 50002, True),                # Long-running community server
        ("electrum.hodlister.co", 50002, True),     # Redundant connection
        ("electrum3.bluewallet.io", 50002, True),   # Maintained by BlueWallet
    ]

    def __init__(self, host: str, port: int, use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.reader = None
        self.writer = None
        self.id_counter = 0

    @classmethod
    def get_random_public_server(cls):
        """Returns a random public server from the list"""
        return random.choice(cls.PUBLIC_SERVERS)

    async def connect(self):
        """Try to connect, with fallback to public servers if local fails"""
        try:
            if self.use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                self.reader, self.writer = await asyncio.open_connection(
                    self.host,
                    self.port,
                    ssl=ssl_context,
                    limit=2**24
                )
            else:
                self.reader, self.writer = await asyncio.open_connection(
                    self.host,
                    self.port,
                    limit=2**24
                )
            print(f"Connected to ElectrumX at {self.host}:{self.port}")
            return True
        except ConnectionError as e:
            print(f"Failed to connect to {self.host}:{self.port} - {str(e)}")
            return False

    @classmethod
    async def create_with_fallback(cls):
        """Factory method that tries local server first, then falls back to public servers"""
        # Try local server first
        client = cls("127.0.0.1", 50001, False)
        if await client.connect():
            return client

        print("Local server connection failed, trying public servers...")

        # Try public servers in random order
        servers = cls.PUBLIC_SERVERS.copy()
        random.shuffle(servers)

        for host, port, use_ssl in servers:
            print(f"Trying {host}:{port}...")
            client = cls(host, port, use_ssl)
            if await client.connect():
                return client

        raise ConnectionRefusedError("Failed to connect to any Electrum server")

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            print("Connection closed.")

    async def send_request(self, method: str, params: list, retries=3) -> dict:
        """Send request to Electrum server with retries, backoff, and reconnection"""
        max_backoff = 10.0  # Maximum backoff time in seconds

        for attempt in range(retries):
            try:
                self.id_counter += 1
                req = {"id": self.id_counter, "method": method, "params": params}
                req_str = json.dumps(req) + "\n"

                try:
                    self.writer.write(req_str.encode())
                    await self.writer.drain()

                    # Match server timeout (slightly less to account for network latency)
                    line = await asyncio.wait_for(self.reader.readline(), timeout=28.0)
                    if not line:
                        raise ConnectionError("No response; connection may be closed.")
                    response = json.loads(line.decode())

                    # Add capped exponential backoff between requests
                    backoff = min(0.1 * (2 ** attempt), max_backoff)
                    await asyncio.sleep(backoff)
                    return response

                except asyncio.TimeoutError:
                    if attempt < retries - 1:
                        print(f"Server busy, retrying {method} (attempt {attempt + 1}/{retries})...")
                        backoff = min(1.0 * (2 ** attempt), max_backoff)
                        await asyncio.sleep(backoff)
                        continue
                    raise

                except (ConnectionError, BrokenPipeError, socket.error) as e:
                    print(f"Connection lost ({str(e)}), attempting to reconnect...")
                    # Try to reconnect
                    if await self.connect():
                        print("Reconnected successfully, retrying request...")
                        # Reset attempt counter after successful reconnection
                        attempt = 0
                        continue
                    else:
                        print("Reconnection failed, trying another server...")
                        # Try a different server
                        host, port, use_ssl = self.get_random_public_server()
                        self.host = host
                        self.port = port
                        self.use_ssl = use_ssl
                        if await self.connect():
                            print(f"Connected to new server {host}:{port}, retrying request...")
                            # Reset attempt counter after successful server switch
                            attempt = 0
                            continue
                        raise

            except Exception as e:
                print(f"-- DEBUG 2: {type(e)} | {e}")
                if attempt < retries - 1:
                    print(f"Error, retrying {method}...")
                    backoff = min(1.0 * (2 ** attempt), max_backoff)
                    await asyncio.sleep(backoff)
                    continue
                print(f"Error in send_request for {method}: {e}")
                raise

    async def get_history(self, scripthash: str) -> list:
        resp = await self.send_request("blockchain.scripthash.get_history", [scripthash])
        return resp.get("result", [])

    async def get_transaction(self, tx_hash: str) -> dict:
        """Get transaction details. Set verbose=True to include input addresses"""
        try:
            resp = await self.send_request("blockchain.transaction.get", [tx_hash, 1])  # 1 for verbose
            result = resp.get("result", {})
            # Handle case where result is a string (raw tx) or list
            if isinstance(result, (str, list)):
                return {"vin": [], "vout": []}
            return result
        except Exception as e:
            print(f"-- DEBUG 209: {type(e)} | {e}")
            print(f"Error getting transaction {tx_hash}: {type(e)} {e} | Cause: {type(e.__cause__)} {e.__cause__}")
            return {"vin": [], "vout": []}

    async def get_input_address(self, txid: str, vout: int) -> str:
        """Get address from a specific output of a transaction"""
        try:
            tx = await self.get_transaction(txid)
            if vout < len(tx.get("vout", [])):
                output = tx["vout"][vout]
                spk = output.get("scriptPubKey", {})
                if "address" in spk:
                    return spk["address"]
                elif "addresses" in spk and spk["addresses"]:
                    return spk["addresses"][0]
        except Exception as e:
            print(f"-- DEBUG 225: {type(e)} | {e}")
            print(f"Error getting input address for {txid}:{vout}: {type(e)} {e} | Cause: {type(e.__cause__)} {e.__cause__}")
        return None

    async def get_address_balance(self, address: str) -> dict:
        """Get balance for a specific address"""
        scripthash = address_to_scripthash(address)
        resp = await self.send_request("blockchain.scripthash.get_balance", [scripthash])
        result = resp.get("result", {})
        # Convert satoshis to BTC
        confirmed = result.get("confirmed", 0) / 100000000
        unconfirmed = result.get("unconfirmed", 0) / 100000000
        return {"confirmed": confirmed, "unconfirmed": unconfirmed}
