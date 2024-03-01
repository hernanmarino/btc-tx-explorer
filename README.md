# Bitcoin Transaction Explorer

A Python-based tool for exploring Bitcoin transactions and their relationships. This interactive explorer allows you to follow transaction chains both forwards and backwards, while also providing insights into address relationships and wallet patterns.

## Features

- **Transaction Chain Exploration**
  - Follow transaction flows in both directions
  - Trace where funds came from (backward tracing)
  - Track where funds went (forward tracing)
  - Configurable exploration depth (default: 16 levels)

- **Comprehensive Transaction Details**
  - Input and output addresses
  - Transaction amounts
  - Script types used
  - Balance information for addresses
  - Confirmation status

- **Advanced Analysis Features**
  - Address relationship detection
  - Change output identification
  - Address type classification:
    - Legacy (P2PKH)
    - P2SH and Nested SegWit
    - Native SegWit (P2WPKH)
    - Taproot (P2TR)

- **Balance Tracking**
  - Real-time balance checking
  - Unconfirmed transaction detection
  - Aggregate balance calculations
  - Historical balance analysis

## Requirements

- Python 3.7+
- `python-bitcoinlib`
- Internet connection for ElectrumX server access

## Installation

```bash
# Clone the repository
git clone [repository-url]

# Install dependencies
pip install python-bitcoinlib
```

## Usage

```bash
python main.py
```

Start by entering a Bitcoin address or transaction ID. The tool will:
1. Fetch the transaction history
2. Allow you to explore related transactions
3. Show detailed information about each transaction
4. Display current balances of involved addresses

## How It Works

1. **Network Connection**
   - Connects to ElectrumX servers for blockchain data
   - Multiple public servers with automatic fallback
   - Secure SSL connections

2. **Transaction Exploration**
   - Follows transaction chains in both directions
   - Shows detailed transaction information
   - Maps relationships between transactions
   - Identifies patterns in transaction flows

3. **Analysis Features**
   - Transaction pattern recognition
   - Script type identification
   - Address clustering capabilities
   - Change output detection

4. **Data Reporting**
   - Transaction details and relationships
   - Address balances and history
   - Confirmation status
   - Aggregate statistics

## Limitations

- Dependent on ElectrumX server availability
- Rate limited by server responses
- Maximum exploration depth may limit very long chains
- Historical data may be incomplete on some servers

## Privacy Considerations

This tool provides insights into public blockchain data. Users should:
- Be aware of blockchain transparency implications
- Understand transaction privacy best practices
- Use responsibly when exploring others' transactions

## Contributing

Contributions are welcome! Areas for improvement include:
- Additional transaction analysis features
- Performance optimization
- Enhanced visualization options
- User interface improvements
- Additional server support

## License

[TBD]

## Disclaimer

This tool is for educational and research purposes only. While it can be used to explore public blockchain data, users should respect privacy concerns and use the tool responsibly.