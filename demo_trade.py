import os
import json
import time
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv

from poly_trading_client import PolyTradingClient, OrderParams


@dataclass
class EnvConfig:
    base_url: str
    signer_address: str
    private_key: str
    funder_address: Optional[str]
    signature_type: int
    api_key: Optional[str]
    api_secret: Optional[str]
    api_passphrase: Optional[str]
    token_id: str
    side: str
    price: float
    size: float
    order_type: str


def read_env() -> EnvConfig:
    load_dotenv()
    return EnvConfig(
        base_url=os.getenv("BASE_URL", "https://clob.polymarket.com"),
        signer_address=os.getenv("SIGNER_ADDRESS", "").strip(),
        private_key=os.getenv("PRIVATE_KEY", "").strip(),
        funder_address=os.getenv("FUNDER_ADDRESS", "").strip() or None,
        signature_type=int(os.getenv("SIGNATURE_TYPE", "0")),
        api_key=os.getenv("API_KEY", "").strip() or None,
        api_secret=os.getenv("API_SECRET", "").strip() or None,
        api_passphrase=os.getenv("API_PASSPHRASE", "").strip() or None,
        token_id=os.getenv("TOKEN_ID", "").strip(),
        side=os.getenv("SIDE", "BUY").strip(),
        price=float(os.getenv("PRICE", "0.05")),
        size=float(os.getenv("SIZE", "1.0")),
        order_type=os.getenv("ORDER_TYPE", "FOK").strip(),
    )


def main() -> None:
    cfg = read_env()
    if not cfg.signer_address or not cfg.private_key:
        raise SystemExit("SIGNER_ADDRESS and PRIVATE_KEY are required in .env")

    # Derive API creds if not provided
    if not (cfg.api_key and cfg.api_secret and cfg.api_passphrase):
        api_key, api_secret, passphrase = PolyTradingClient.derive_api_credentials(
            cfg.signer_address, cfg.private_key, cfg.base_url
        )
    else:
        api_key, api_secret, passphrase = cfg.api_key, cfg.api_secret, cfg.api_passphrase

    client = PolyTradingClient(
        base_url=cfg.base_url,
        api_key=api_key,
        api_secret=api_secret,
        api_passphrase=passphrase,
        signer_address=cfg.signer_address,
        signer_private_key=cfg.private_key,
        funder_address=cfg.funder_address,
        signature_type=cfg.signature_type,
    )

    # L2 auth sanity
    status, body = client.test_l2_auth()
    print(f"L2 auth: {status} {body}")
    if status != 200:
        raise SystemExit("L2 auth failed")

    if not cfg.token_id:
        raise SystemExit("TOKEN_ID is required in .env to place an order")

    exp = int(time.time()) + 120
    order = client.build_signed_order(
        OrderParams(
            token_id=cfg.token_id,
            price=cfg.price,
            size_shares=cfg.size,
            side=cfg.side,
            expiration_unix=exp,
        )
    )

    st, resp = client.place_order(order, cfg.order_type, client_id="py_demo_001")
    print("Place order:", st, resp)

    order_id = None
    try:
        jo = json.loads(resp)
        order_id = jo.get("orderId") or jo.get("id") or jo.get("order_id")
    except Exception:
        pass

    # Optional: cancel if we got an id
    if order_id:
        time.sleep(0.5)
        st2, resp2 = client.cancel_order(order_id=order_id)
        print("Cancel order:", st2, resp2)

        # Fetch status (best-effort)
        st3, resp3 = client.get_order_status(order_id)
        print("Order status:", st3, resp3)


if __name__ == "__main__":
    main()
