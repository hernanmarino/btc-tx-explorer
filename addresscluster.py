from helpers import is_round_number, extract_output_addresses, get_input_script_types, get_output_script_types

class AddressCluster:
    """
    A class for clustering related Bitcoin addresses.
    
    This class maintains a set of addresses that are likely owned by the same entity,
    using various heuristics to identify related addresses through transaction analysis.
    """
    
    def __init__(self, initial_address: str):
        """
        Initialize the address cluster with a starting address.
        
        Args:
            initial_address (str): The first address to add to the cluster.
        """
        self.addresses = {initial_address}

    def add_address(self, address: str) -> None:
        """
        Add an address to the cluster if it's not None.
        
        Args:
            address (str): The address to add to the cluster.
        """
        if address:
            self.addresses.add(address)

    def is_own_address(self, address: str) -> bool:
        """
        Check if an address belongs to the cluster.
        
        Args:
            address (str): The address to check.
            
        Returns:
            bool: True if the address is in the cluster, False otherwise.
        """
        return address in self.addresses

    def analyze_transaction(self, tx: dict) -> None:
        """
        Analyze a transaction to identify related addresses.
        
        This method uses several heuristics to identify addresses that are likely
        owned by the same entity:
        1. Common input ownership
        2. Round number amounts for payments
        3. Script type consistency
        4. Single output consolidation
        
        Args:
            tx (dict): The transaction to analyze, containing 'vin' and 'vout' fields.
        """
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
                            self.add_address(addr)

            # Single output case: likely internal transfer
            if len(output_addresses) == 1:
                self.add_address(output_addresses[0])

            # Script type consistency heuristic for change detection
            if any(self.is_own_address(addr) for addr in input_addresses):
                # We own at least one input, check for change outputs
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
                                    self.add_address(addr)

        # --- Case 2: We own one of the outputs ---
        if any(self.is_own_address(addr) for addr in output_addresses):
            # Check script type consistency first (strong heuristic)
            input_script_types = get_input_script_types(input_addresses)
            if len(input_script_types) == 1:  # All inputs have same script type
                input_script_type = input_script_types.pop()
                # Count outputs matching input script type
                matching_type_outputs = []
                for i, vout in enumerate(vouts):
                    output_script_types = get_output_script_types(vout)
                    if len(output_script_types) == 1 and output_script_types[0] == input_script_type:
                        matching_type_outputs.append(i)

                # If exactly one output matches input type and we own it, we own all inputs
                if len(matching_type_outputs) == 1:
                    vout = vouts[matching_type_outputs[0]]
                    if any(self.is_own_address(addr) for addr in extract_output_addresses(vout)):
                        print("Script type consistency: We own the only output matching input type")
                        for addr in input_addresses:
                            self.add_address(addr)

            # Continue with existing round number heuristics
            if len(output_addresses) == 1:
                # Single output case: if we own it, likely consolidation
                for addr in input_addresses:
                    self.add_address(addr)

            elif len(output_addresses) == 2:
                # Two outputs case: check round number heuristic
                our_output_idx = None
                for i, vout in enumerate(vouts):
                    addrs = extract_output_addresses(vout)
                    if any(self.is_own_address(addr) for addr in addrs):
                        our_output_idx = i
                        break

                if our_output_idx is not None:
                    amounts = [v.get("value", 0) for v in vouts]
                    other_idx = 1 - our_output_idx
                    # We're the sender if our output is non-round AND other is round
                    if not is_round_number(amounts[our_output_idx]) and is_round_number(amounts[other_idx]):
                        for addr in input_addresses:
                            self.add_address(addr)
