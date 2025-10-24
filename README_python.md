## Polymarket Python Trading Client

This folder contains a minimal Python client and demo to validate trading logic against Polymarket CLOB before editing the VB.NET code.

Files:
- `requirements.txt` – Python deps
- `.env.example` – environment template
- `poly_trading_client.py` – raw HTTP client with EIP-712 signing + L2 HMAC
- `demo_trade.py` – demo to place, cancel, and fetch status

### Setup
1. Create a virtual environment and install deps:
   - `python -m venv .venv` (Windows: `.venv\Scripts\activate`)
   - `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and fill values:
   - `SIGNER_ADDRESS`, `PRIVATE_KEY` are required
   - Leave `API_KEY`, `API_SECRET`, `API_PASSPHRASE` empty to auto-derive
   - Provide `TOKEN_ID`, `SIDE`, `PRICE`, `SIZE`, `ORDER_TYPE`
3. Run demo:
   - `python demo_trade.py`

### Notes
- Uses the same order schema and HMAC as the VB code to replicate behavior.
- Numeric fields are strings in HTTP payload; EIP-712 uses raw numbers.
- `signatureType` supports 0=EOA, 1=Proxy, 2=Safe.
