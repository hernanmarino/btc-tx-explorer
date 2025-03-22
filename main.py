#!/usr/bin/env python3
import asyncio
import hashlib
import json
from bitcoin.wallet import CBitcoinAddress
from bitcoin.core import CScript
import random
import ssl
from bech32 import bech32_decode, convertbits, decode
#from bitcoinlib.encoding import addr_bech32_to_pubkeyhash
import segwit_addr  # Add this import

# --- Helper Functions ---
def address_to_scripthash(address_str: str) -> str:
    """
    Convert address to scripthash with Taproot support.
    """
    try:
        # First try the standard bitcoin library conversion
        addr = CBitcoinAddress(address_str)
        script = addr.to_scriptPubKey()
        h = hashlib.sha256(bytes(script)).digest()
        return h[::-1].hex()
    except Exception as e:
        # Handle Taproot (P2TR) addresses using segwit_addr
        if address_str.startswith('bc1p'):
            # Decode Taproot address using segwit_addr
            witver, witprog = segwit_addr.decode('bc', address_str)
            if witver is None or witver != 1 or len(witprog) != 32:
                raise ValueError(f"Invalid Taproot address: {address_str}")
            
            # Create P2TR script
            script = bytes([0x51, 0x20]) + bytes(witprog)  # 0x51 is OP_1, 0x20 is push 32 bytes
            h = hashlib.sha256(script).digest()
            return h[::-1].hex()
        else:
            raise ValueError(f"Unsupported address format: {address_str}")

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
        try:
            self.id_counter += 1
            req = {"id": self.id_counter, "method": method, "params": params}
            req_str = json.dumps(req) + "\n"
            self.writer.write(req_str.encode())
            await self.writer.drain()
            
            # Add timeout to read operation
            try:
                line = await asyncio.wait_for(self.reader.readline(), timeout=10.0)  # 10 second timeout
            except asyncio.TimeoutError:
                print(f"Timeout waiting for response to {method} with params {params}")
                raise
            
            if not line:
                raise Exception("No response; connection may be closed.")
            response = json.loads(line.decode())
            return response
        except Exception as e:
            print(f"Error in send_request for {method}: {e}")
            raise

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


def extract_input_address(vin):
    """Extract address from input, considering prevout structure"""
    # In verbose mode, address is directly in the vin
    if "address" in vin:
        return vin["address"]
    # Fallback to prevout if present
    prevout = vin.get("prevout", {})
    if "scriptPubKey" in prevout:
        spk = prevout["scriptPubKey"]
        if "address" in spk:
            return spk["address"]
        if "addresses" in spk and spk["addresses"]:
            return spk["addresses"][0]
    return None

def extract_output_addresses(vout):
    """Extract addresses from output, handling different script types"""
    spk = vout.get("scriptPubKey", {})
    addresses = []
    
    # Handle modern format
    if "address" in spk:
        addresses.append(spk["address"])
    # Handle legacy format
    elif "addresses" in spk:
        addresses.extend(spk["addresses"])
    # Skip non-address outputs (OP_RETURN etc)
    
    return addresses

def is_round_number(amount, precision=6):
    rounded = round(amount, precision)
    return abs(rounded - amount) < 1e-8

# Add these helper functions after the existing helper functions:
def get_script_type(address: str) -> str:
    """Determine the script type of an address"""
    if address.startswith('1'):
        return 'p2pkh'  # Legacy
    elif address.startswith('3'):
        return 'p2sh'   # P2SH or Nested SegWit
    elif address.startswith('bc1q'):
        return 'p2wpkh' # Native SegWit
    elif address.startswith('bc1p'):
        return 'p2tr'   # Taproot
    return 'unknown'

def get_input_script_types(input_addresses: list) -> set:
    """Get unique script types from input addresses"""
    return {get_script_type(addr) for addr in input_addresses if addr}

def get_output_script_types(vout: dict) -> list:
    """Get script types for an output"""
    addresses = extract_output_addresses(vout)
    return [get_script_type(addr) for addr in addresses if addr]

# --- Cluster Class ---
class AddressCluster:
    def __init__(self, initial_address):
        self.addresses = {initial_address}
        self.change_addresses = set()

    def add_address(self, address):
        if address:
            self.addresses.add(address)

    def add_change_address(self, address):
        if address:
            self.change_addresses.add(address)

    def is_own_address(self, address):
        return address in self.addresses or address in self.change_addresses

    def analyze_transaction(self, tx):
        # Get input addresses from our added field
        input_addresses = set(tx.get("input_addresses", []))

        # Extract output addresses (flatten list)
        output_addresses = []
        vouts = tx.get("vout", [])
        for vout in vouts:
            addrs = extract_output_addresses(vout)
            output_addresses.extend(addrs)

        # --- Case 1: We own one of the inputs ---
        if any(self.is_own_address(addr) for addr in input_addresses):
            # Add all inputs as ours (common-input ownership)
            for addr in input_addresses:
                self.add_address(addr)

            # Handle two-output case (payment + change)
            if len(vouts) == 2:
                amounts = [v.get("value", 0) for v in vouts]
                # Find which output has a round amount (likely payment)
                round_amount_idx = None
                for i, amount in enumerate(amounts):
                    if is_round_number(amount):
                        round_amount_idx = i
                        break
                
                # If we found a round amount, the other output is likely our change
                if round_amount_idx is not None:
                    change_idx = 1 - round_amount_idx
                    for addr in extract_output_addresses(vouts[change_idx]):
                        if not self.is_own_address(addr):
                            self.add_change_address(addr)

            # Single output case: likely internal transfer
            if len(output_addresses) == 1:
                self.add_address(output_addresses[0])

            # Script type consistency heuristic for change detection
            input_script_types = get_input_script_types(input_addresses)
            if len(input_script_types) == 1:  # All inputs have same script type
                input_script_type = input_script_types.pop()
                # Check each output
                for vout in vouts:
                    output_script_types = get_output_script_types(vout)
                    # If only one output matches input script type, it's likely change
                    if len(output_script_types) == 1 and output_script_types[0] == input_script_type:
                        for addr in extract_output_addresses(vout):
                            if not self.is_own_address(addr):
                                print(f"Script type consistency: Found likely change address {addr}")
                                self.add_change_address(addr)

        # --- Case 2: We own one of the outputs ---
        if any(self.is_own_address(addr) for addr in output_addresses):
            # Single output case: if we own it, likely consolidation, so inputs are ours
            if len(output_addresses) == 1:
                for addr in input_addresses:
                    self.add_address(addr)
            
            # Two outputs case: need to determine if we're sender or receiver
            elif len(output_addresses) == 2:
                # Find our output index
                our_output_idx = None
                for i, vout in enumerate(vouts):
                    addrs = extract_output_addresses(vout)
                    if any(self.is_own_address(addr) for addr in addrs):
                        our_output_idx = i
                        break
                
                if our_output_idx is not None:
                    amounts = [v.get("value", 0) for v in vouts]
                    other_idx = 1 - our_output_idx
                    # We're the sender if:
                    # 1. Our output is non-round (change address) AND
                    # 2. The other output is round (payment)
                    if not is_round_number(amounts[our_output_idx]) and is_round_number(amounts[other_idx]):
                        # We're the sender, so we own all inputs
                        for addr in input_addresses:
                            self.add_address(addr)
                        
                        # Apply script type consistency check for additional confidence
                        input_script_types = get_input_script_types(input_addresses)
                        if len(input_script_types) == 1:
                            input_script_type = input_script_types.pop()
                            our_output_script_types = get_output_script_types(vouts[our_output_idx])
                            if len(our_output_script_types) == 1 and our_output_script_types[0] == input_script_type:
                                print(f"Script type consistency confirms change address pattern")

# --- Recursive Tracing Function ---
async def trace_inputs(tx_hash, client, visited, cluster, depth=0, max_depth=16):
    try:
        print(f"Depth: {depth}, Visited transactions: {len(visited)}")  # Debug print
        
        if tx_hash in visited or depth >= max_depth:
            print(f"Stopping trace: {'Already visited' if tx_hash in visited else 'Max depth reached'}")
            return
        visited.add(tx_hash)
        
        try:
            print(f"Fetching transaction {tx_hash}")  # Debug print
            tx = await client.get_transaction(tx_hash)
        except Exception as e:
            print(f"Error fetching transaction {tx_hash}: {e}")
            return
        
        # Get input addresses by looking up previous transactions
        input_addresses = set()
        for vin in tx.get("vin", []):
            if "coinbase" in vin:
                continue
            prev_txid = vin.get("txid")
            prev_vout = vin.get("vout")
            if prev_txid is not None and prev_vout is not None:
                addr = await client.get_input_address(prev_txid, prev_vout)
                if addr:
                    input_addresses.add(addr)
        
        # Add input addresses to transaction for analysis
        tx["input_addresses"] = list(input_addresses)
        
        cluster.analyze_transaction(tx)

        found_related = any(
            cluster.is_own_address(extract_input_address(vin))
            for vin in tx.get("vin", [])
            if extract_input_address(vin) is not None
        )
        if not found_related:
            print(f"Stopping trace at transaction {tx_hash} (no related inputs)")
            return

        print(f"Tracing transaction {tx_hash}")
        if is_coinbase(tx):
            print("Reached coinbase transaction")
            return
            
        for vin in tx.get("vin", []):
            if "coinbase" in vin:
                continue
            prev_txid = vin.get("txid")
            if prev_txid:
                await trace_inputs(prev_txid, client, visited, cluster, depth + 1, max_depth)
    except Exception as e:
        print(f"Error processing transaction {tx_hash}: {e}")

# Add this new function after trace_inputs:
async def trace_outputs(address, client, visited, cluster, depth=0, max_depth=16):
    print(f"Tracing outputs for {address} at depth {depth}")  # Debug print
    if depth >= max_depth:
        print(f"Max depth reached for address {address}")
        return
        
    try:
        scripthash = address_to_scripthash(address)
        print(f"Getting history for {address}")  # Debug print
        history = await client.get_history(scripthash)
        print(f"Found {len(history)} transactions for {address}")  # Debug print
        
        for item in history:
            tx_hash = item.get("tx_hash")
            if tx_hash in visited:
                continue
                
            visited.add(tx_hash)
            tx = await client.get_transaction(tx_hash)
            
            # Get input addresses
            input_addresses = set()
            for vin in tx.get("vin", []):
                if "coinbase" in vin:
                    continue
                prev_txid = vin.get("txid")
                prev_vout = vin.get("vout")
                if prev_txid is not None and prev_vout is not None:
                    addr = await client.get_input_address(prev_txid, prev_vout)
                    if addr:
                        input_addresses.add(addr)
            
            tx["input_addresses"] = list(input_addresses)
            
            # Analyze the transaction
            cluster.analyze_transaction(tx)
            
            # Get output addresses and recursively trace them if they belong to our cluster
            for vout in tx.get("vout", []):
                for out_addr in extract_output_addresses(vout):
                    if cluster.is_own_address(out_addr) and out_addr != address:
                        print(f"Following output address: {out_addr}")
                        await trace_outputs(out_addr, client, visited, cluster, depth + 1, max_depth)
                        
    except Exception as e:
        print(f"Error tracing outputs for address {address}: {e}")


# --- Main function ---
async def main():
    try:
        client = await ElectrumXClient.create_with_fallback()
        #initial_addr = "bc1qqrulkslglepwe4cenge7wa7mrje0n0vkrd48l2"
        initial_addr = "bc1pknqtmct768xd8ulr5ulnptmkddemzsr4s0s46xf58krlsqdw89tsx9ssya"
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
