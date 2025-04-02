import hashlib
from bitcoin.wallet import CBitcoinAddress
from bitcoin.base58 import InvalidBase58Error
import segwit_addr

# Constants
TX_COUNT_THRESHOLD = 100  # Maximum number of transactions to process per address
TRACE_MAX_DEPTH = 5      # Maximum depth for transaction tracing
ROUND_NUMBER_PRECISION = 6  # Decimal places for round number comparison

def address_to_scripthash(address_str: str) -> str:
    """
    Convert a Bitcoin address to its corresponding scripthash.
    
    This function supports multiple address formats including legacy (P2PKH), 
    P2SH, SegWit (P2WPKH), and Taproot (P2TR) addresses.
    
    Args:
        address_str (str): The Bitcoin address to convert.
        
    Returns:
        str: The scripthash in hexadecimal format, byte-reversed as required by ElectrumX.
        
    Raises:
        ValueError: If the address format is unsupported or invalid.
        InvalidBase58Error: If the address contains invalid base58 characters.
    """
    try:
        # First try the standard bitcoin library conversion
        addr = CBitcoinAddress(address_str)
        script = addr.to_scriptPubKey()
        h = hashlib.sha256(bytes(script)).digest()
        return h[::-1].hex()
    except InvalidBase58Error as e:
        # Handle Taproot (P2TR) addresses using segwit_addr
        if address_str.startswith('bc1p'):
            # Decode Taproot address using segwit_addr
            witver, witprog = segwit_addr.decode('bc', address_str)
            if witver is None or witver != 1 or len(witprog) != 32:
                raise ValueError(f"Invalid Taproot address: {address_str}") from e

            # Create P2TR script
            script = bytes([0x51, 0x20]) + bytes(witprog)  # 0x51 is OP_1, 0x20 is push 32 bytes
            h = hashlib.sha256(script).digest()
            return h[::-1].hex()
        else:
            raise ValueError(f"Unsupported address format: {address_str}") from e


def is_coinbase(tx: dict) -> bool:
    """
    Check if a transaction is a coinbase transaction.
    
    Args:
        tx (dict): The transaction dictionary to check.
        
    Returns:
        bool: True if the transaction is a coinbase transaction, False otherwise.
    """
    vin = tx.get("vin", [])
    return len(vin) > 0 and "coinbase" in vin[0]


def is_round_number(amount: float, precision: int = ROUND_NUMBER_PRECISION) -> bool:
    """
    Check if a number is "round" within a given precision.
    
    A number is considered "round" if it's close to its rounded value
    within a small epsilon. This is useful for identifying likely payment
    amounts in Bitcoin transactions.
    
    Args:
        amount (float): The number to check.
        precision (int, optional): Number of decimal places to consider. 
                                 Defaults to ROUND_NUMBER_PRECISION.
        
    Returns:
        bool: True if the number is round, False otherwise.
    """
    rounded = round(amount, precision)
    return abs(rounded - amount) < 1e-8


def extract_input_address(vin: dict) -> str:
    """
    Extract the address from a transaction input.
    
    This function handles different input formats and structures,
    including both modern and legacy transaction formats.
    
    Args:
        vin (dict): The transaction input dictionary.
        
    Returns:
        str: The extracted address, or None if no address is found.
    """
    # In verbose mode, address is directly in the vin
    if "address" in vin:
        return vin["address"]
    # Fallback to prevout if present
    prevout = vin.get("prevout", {})
    if "scriptPubKey" in prevout:
        script_pub_key = prevout["scriptPubKey"]
        if "address" in script_pub_key:
            return script_pub_key["address"]
        if "addresses" in script_pub_key and script_pub_key["addresses"]:
            return script_pub_key["addresses"][0]
    return None


def extract_output_addresses(vout: dict) -> list:
    """
    Extract addresses from a transaction output.
    
    This function handles different output formats and script types,
    including both modern and legacy transaction formats.
    
    Args:
        vout (dict): The transaction output dictionary.
        
    Returns:
        list: List of addresses found in the output.
    """
    script_pub_key = vout.get("scriptPubKey", {})
    addresses = []

    # Handle modern format
    if "address" in script_pub_key:
        addresses.append(script_pub_key["address"])
    # Handle legacy format
    elif "addresses" in script_pub_key:
        addresses.extend(script_pub_key["addresses"])
    # Skip non-address outputs (OP_RETURN etc)

    return addresses


def get_script_type(address: str) -> str:
    """
    Determine the script type of a Bitcoin address.
    
    Args:
        address (str): The Bitcoin address to analyze.
        
    Returns:
        str: The script type ('p2pkh', 'p2sh', 'p2wpkh', 'p2tr', or 'unknown').
    """
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
    """
    Get unique script types from a list of input addresses.
    
    Args:
        input_addresses (list): List of Bitcoin addresses.
        
    Returns:
        set: Set of unique script types found in the addresses.
    """
    return {get_script_type(addr) for addr in input_addresses if addr}


def get_output_script_types(vout: dict) -> list:
    """
    Get script types for all addresses in a transaction output.
    
    Args:
        vout (dict): The transaction output dictionary.
        
    Returns:
        list: List of script types for all addresses in the output.
    """
    addresses = extract_output_addresses(vout)
    return [get_script_type(addr) for addr in addresses if addr]


async def trace_inputs(tx_hash: str, client, visited: set, cluster, depth: int = 0, max_depth: int = TRACE_MAX_DEPTH) -> None:
    """
    Recursively trace transaction inputs to find related addresses.
    
    This function follows the input chain of a transaction to discover
    addresses that are likely owned by the same entity.
    
    Args:
        tx_hash (str): The transaction hash to trace.
        client: The ElectrumX client instance.
        visited (set): Set of already visited transaction hashes.
        cluster: The AddressCluster instance to update.
        depth (int, optional): Current recursion depth. Defaults to 0.
        max_depth (int, optional): Maximum recursion depth. Defaults to TRACE_MAX_DEPTH.
    """
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
            print(f"-- DEBUG 425: {type(e)} | {e}")
            print(f"Error fetching transaction {tx_hash}: {type(e)} {e} | Cause: {type(e.__cause__)} {e.__cause__}")
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
            cluster.is_own_address(addr) for addr in input_addresses
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
        print(f"-- DEBUG 466: {type(e)} | {e}")
        print(f"Error processing transaction {tx_hash}: {type(e)} {e} | Cause: {type(e.__cause__)} {e.__cause__}")


async def trace_outputs(address: str, client, visited: set, cluster, depth: int = 0, max_depth: int = TRACE_MAX_DEPTH) -> None:
    """
    Recursively trace transaction outputs to find related addresses.
    
    This function follows the output chain of an address to discover
    addresses that are likely owned by the same entity.
    
    Args:
        address (str): The Bitcoin address to trace.
        client: The ElectrumX client instance.
        visited (set): Set of already visited transaction hashes.
        cluster: The AddressCluster instance to update.
        depth (int, optional): Current recursion depth. Defaults to 0.
        max_depth (int, optional): Maximum recursion depth. Defaults to TRACE_MAX_DEPTH.
    """
    print(f"Tracing outputs for {address} at depth {depth}")  # Debug print
    if depth >= max_depth:
        print(f"Max depth reached for address {address}")
        return

    try:
        scripthash = address_to_scripthash(address)
        print(f"Getting history for {address}")  # Debug print
        history = await client.get_history(scripthash)
        tx_count = len(history)
        print(f"Found {tx_count} transactions for {address}")  # Debug print

        # Skip addresses with too many transactions
        if tx_count > TX_COUNT_THRESHOLD:
            print(f"WARNING: Address {address} has too many transactions ({tx_count}). Skipping to avoid timeout.")
            return

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
        print(f"Error tracing outputs for address {address}: {type(e)} {e} | Cause: {type(e.__cause__)} {e.__cause__}")
