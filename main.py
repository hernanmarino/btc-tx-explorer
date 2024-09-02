#!/usr/bin/env python3
import asyncio
import hashlib
import json
from bitcoin.wallet import CBitcoinAddress
from bitcoin.core import CScript
import random
import ssl

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
