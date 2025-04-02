import asyncio
import json
import random
import socket
import ssl
from helpers import address_to_scripthash

class ElectrumXClient:
    """
    A client for interacting with ElectrumX servers.
    
    This class provides methods to connect to and communicate with ElectrumX servers,
    supporting both local and public servers with automatic fallback mechanisms.
    """
    
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

    def __init__(self, host: str, port: int, use_ssl: bool = False):
        """
        Initialize the ElectrumX client.
        
        Args:
            host (str): The hostname of the ElectrumX server.
            port (int): The port number of the ElectrumX server.
            use_ssl (bool, optional): Whether to use SSL for the connection. Defaults to False.
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.reader = None
        self.writer = None
        self.id_counter = 0

    @classmethod
    def get_random_public_server(cls) -> tuple:
        """
        Get a random public ElectrumX server from the predefined list.
        
        Returns:
            tuple: A tuple containing (host, port, use_ssl) for a random server.
        """
        return random.choice(cls.PUBLIC_SERVERS)

    async def connect(self) -> bool:
        """
        Establish a connection to the ElectrumX server.
        
        This method attempts to connect to the server using either SSL or plain TCP,
        depending on the use_ssl flag set during initialization.
        
        Returns:
            bool: True if the connection was successful, False otherwise.
        """
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
        """
        Create a client instance with automatic fallback to public servers.
        
        This factory method first attempts to connect to a local ElectrumX server.
        If that fails, it tries connecting to public servers in random order.
        
        Returns:
            ElectrumXClient: An initialized and connected client instance.
            
        Raises:
            ConnectionRefusedError: If unable to connect to any server.
        """
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

    async def close(self) -> None:
        """
        Close the connection to the ElectrumX server.
        
        This method properly closes the writer and waits for the connection
        to be fully closed.
        """
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            print("Connection closed.")

    async def send_request(self, method: str, params: list, retries: int = 3) -> dict:
        """
        Send a request to the ElectrumX server with retry logic.
        
        This method implements exponential backoff and automatic reconnection
        in case of connection issues. It also handles server timeouts and
        connection errors gracefully.
        
        Args:
            method (str): The RPC method to call.
            params (list): The parameters for the RPC method.
            retries (int, optional): Number of retry attempts. Defaults to 3.
            
        Returns:
            dict: The server's response.
            
        Raises:
            Exception: If all retry attempts fail.
        """
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
        """
        Get the transaction history for a scripthash.
        
        Args:
            scripthash (str): The scripthash to query.
            
        Returns:
            list: List of transactions associated with the scripthash.
        """
        resp = await self.send_request("blockchain.scripthash.get_history", [scripthash])
        return resp.get("result", [])

    async def get_transaction(self, tx_hash: str) -> dict:
        """
        Get detailed information about a transaction.
        
        Args:
            tx_hash (str): The transaction hash to query.
            
        Returns:
            dict: Transaction details including inputs and outputs.
        """
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
        """
        Get the address associated with a specific transaction output.
        
        Args:
            txid (str): The transaction ID.
            vout (int): The output index.
            
        Returns:
            str: The address associated with the output, or None if not found.
        """
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
        """
        Get the balance for a Bitcoin address.
        
        Args:
            address (str): The Bitcoin address to query.
            
        Returns:
            dict: Dictionary containing confirmed and unconfirmed balances in BTC.
        """
        scripthash = address_to_scripthash(address)
        resp = await self.send_request("blockchain.scripthash.get_balance", [scripthash])
        result = resp.get("result", {})
        # Convert satoshis to BTC
        confirmed = result.get("confirmed", 0) / 100000000
        unconfirmed = result.get("unconfirmed", 0) / 100000000
        return {"confirmed": confirmed, "unconfirmed": unconfirmed}
