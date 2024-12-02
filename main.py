#!/usr/bin/env python3
import asyncio
import hashlib
import json
from bitcoin.wallet import CBitcoinAddress
from bitcoin.core import CScript
import random
import ssl

# --- Helper Functions ---
def address_to_scripthash(address_str: str) -> str:
    """
    Electrum scripthash is the SHA256 of the scriptPubKey (in binary),
    then the resulting hash is reversed (i.e. little-endian hex).
    """
    addr = CBitcoinAddress(address_str)
    script = addr.to_scriptPubKey()
    h = hashlib.sha256(bytes(script)).digest()
    return h[::-1].hex()

def is_coinbase(tx: dict) -> bool:
    vin = tx.get("vin", [])
    return len(vin) > 0 and "coinbase" in vin[0]

# --- ElectrumX Client ---
class ElectrumXClient:
    # List of known public servers (you can add more)
    PUBLIC_SERVERS = [
        ("electrum.blockstream.info", 50002, True),  # (host, port, is_ssl)
        ("electrum.bitaroo.net", 50002, True),
        ("electrum.hodlister.co", 50002, True),
        ("electrum3.hodlister.co", 50002, True),
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
        except Exception as e:
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
        
        raise Exception("Failed to connect to any Electrum server")

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            print("Connection closed.")

    async def send_request(self, method: str, params: list) -> dict:
        self.id_counter += 1
        req = {"id": self.id_counter, "method": method, "params": params}
        req_str = json.dumps(req) + "\n"
        self.writer.write(req_str.encode())
        await self.writer.drain()
        line = await self.reader.readline()
        if not line:
            raise Exception("No response; connection may be closed.")
        response = json.loads(line.decode())
        return response

    async def get_history(self, scripthash: str) -> list:
        resp = await self.send_request("blockchain.scripthash.get_history", [scripthash])
        return resp.get("result", [])

    async def get_transaction(self, tx_hash: str, verbose=True) -> dict:
        """Get transaction details. Set verbose=True to include input addresses"""
        # Add verbose parameter to the request
        resp = await self.send_request("blockchain.transaction.get", [tx_hash, 1])  # 1 for verbose
        return resp.get("result", {})

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
            print(f"Error getting input address for {txid}:{vout}: {e}")
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

# --- Main function ---
async def main():
    try:
        client = await ElectrumXClient.create_with_fallback()
        #initial_addr = "bc1qqrulkslglepwe4cenge7wa7mrje0n0vkrd48l2"
        initial_addr = ""
        cluster = AddressCluster(initial_addr)
        scripthash = address_to_scripthash(initial_addr)
        print(f"Address: {initial_addr}")
        print(f"Scripthash: {scripthash}")

        history = await client.get_history(scripthash)
        if not history:
            print("No transaction history found for this address.")
            return

        print(f"Found {len(history)} transactions for address {initial_addr}.")

        visited_tx = set()
        
        # First do backward tracing
        print("\nPerforming backward tracing...")
        for item in history:
            tx_hash = item.get("tx_hash")
            print(f"\nTracing backward from transaction: {tx_hash}")
            await trace_inputs(tx_hash, client, visited_tx, cluster)
        
        # Then do forward tracing for all discovered addresses
        print("\nPerforming forward tracing...")
        all_addresses = cluster.addresses.union(cluster.change_addresses)
        for addr in all_addresses:
            print(f"\nTracing forward from address: {addr}")
            await trace_outputs(addr, client, visited_tx, cluster)

        print("\n=== Address Cluster Analysis Results ===")
        print(f"Total related addresses found: {len(cluster.addresses) + len(cluster.change_addresses)}")
        
        total_balance = 0
        print("\nMain addresses:")
        for addr in sorted(cluster.addresses):
            balance = await client.get_address_balance(addr)
            total_balance += balance["confirmed"]
            print(f"- {addr}\t\t{balance['confirmed']:.8f} BTC")
            if balance["unconfirmed"] != 0:
                print(f"  Unconfirmed: {balance['unconfirmed']:.8f} BTC")
        
        print("\nChange addresses:")
        for addr in sorted(cluster.change_addresses):
            balance = await client.get_address_balance(addr)
            total_balance += balance["confirmed"]
            print(f"- {addr}\t\t{balance['confirmed']:.8f} BTC")
            if balance["unconfirmed"] != 0:
                print(f"  Unconfirmed: {balance['unconfirmed']:.8f} BTC")
        
        print(f"\nTotal Balance: {total_balance:.8f} BTC")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if client:
            await client.close()

if __name__ == "__main__":
    asyncio.run(main())
