#!/usr/bin/env python3
import hashlib
import segwit_addr  # Make sure this module supports Bech32m (BIP350)

def decode_segwit_address(hrp: str, addr: str):
    """
    Decode a segwit address (supporting both Bech32 and Bech32m).
    Returns a tuple (witver, witprog) where witver is the witness version (an int)
    and witprog is a list of integers (the witness program).
    Raises ValueError if the address is invalid.
    """
    witver, witprog = segwit_addr.decode(hrp, addr)
    if witver is None:
        raise ValueError(f"Invalid segwit address: {addr}")
    return witver, witprog

def address_to_scripthash(address: str) -> str:
    """
    Convert a Bitcoin address (including Taproot addresses starting with 'bc1p')
    to its scripthash. For Taproot addresses (witness version 1+), it builds the
    P2TR script: OP_1 followed by a push of 32 bytes.
    
    The scripthash is computed as the SHA-256 hash of the scriptPubKey, with the
    resulting digest reversed (hex encoded).
    """
    hrp = "bc"  # mainnet; for testnet use "tb"
    witver, witprog = decode_segwit_address(hrp, address)
    
    # Validate witness version and length:
    if not (0 <= witver <= 16):
        raise ValueError(f"Invalid witness version: {witver}")
    # For v0 addresses, the witness program must be 20 or 32 bytes.
    if witver == 0 and len(witprog) not in (20, 32):
        raise ValueError("Invalid witness program length for version 0 address")
    # For Taproot (v1) addresses, the witness program should be exactly 32 bytes.
    if witver != 0 and len(witprog) != 32:
        raise ValueError("Invalid witness program length for Taproot address")
    
    # Build scriptPubKey:
    # For witness version 0, OP_0 is 0x00.
    # For witness versions 1-16, the opcode is 0x50+witver.
    op = (witver + 0x50) if witver else 0x00
    scriptPubKey = bytes([op, len(witprog)]) + bytes(witprog)
    
    # Compute scripthash: sha256(scriptPubKey) and reverse the result.
    h = hashlib.sha256(scriptPubKey).digest()
    return h[::-1].hex()

if __name__ == "__main__":
    # Example Taproot address (Bech32m, starting with 'bc1p')
    taproot_addr = "bc1pknqtmct768xd8ulr5ulnptmkddemzsr4s0s46xf58krlsqdw89tsx9ssya"
    print("Taproot address:", taproot_addr)
    try:
        scripthash = address_to_scripthash(taproot_addr)
        print("Scripthash:", scripthash)
    except Exception as e:
        print("Error:", e)
