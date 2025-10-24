import time
import json
import hmac
import base64
import random
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any

import requests
from eth_account import Account
try:
    from eth_account.messages import encode_structured_data as _encode_structured_data
except Exception:
    _encode_structured_data = None
from eth_utils import keccak
try:
    from eth_abi import encode as abi_encode
except Exception:
    try:
        from eth_abi import encode_abi as abi_encode
    except Exception:
        abi_encode = None
from eth_keys import keys as _eth_keys


# Keep URL-safe Base64 with padding retained

def base64url_encode(data: bytes) -> str:
    b64 = base64.b64encode(data).decode("utf-8")
    return b64.replace("+", "-").replace("/", "_")


def base64url_decode(s: str) -> bytes:
    t = (s or "").strip().replace("-", "+").replace("_", "/")
    rem = len(t) % 4
    if rem:
        t += "=" * (4 - rem)
    return base64.b64decode(t)


EXCHANGE_ADDR = "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e"


def _eip712_encode_and_sign(typed: Dict[str, Any], priv_hex: str) -> str:
    if _encode_structured_data is not None:
        encoded = _encode_structured_data(primitive=typed)
        return Account.sign_message(encoded, private_key=bytes.fromhex(priv_hex)).signature.hex()

    if abi_encode is None:
        raise RuntimeError("eth-account without encode_structured_data and no eth-abi available. Please install eth-account>=0.10 and eth-abi.")

    # Minimal EIP-712 encoder for our fixed types
    domain = typed.get("domain", {})
    message = typed.get("message", {})
    primary = typed.get("primaryType")
    types = typed.get("types", {})

    def type_hash(type_name: str) -> bytes:
        fields = types[type_name]
        sig = type_name + "(" + ",".join(f["type"] + " " + f["name"] for f in fields) + ")"
        return keccak(text=sig)

    def encode_value(t: str, v: Any) -> bytes:
        if t == "string":
            return keccak(text=str(v))
        if t == "bytes":
            return keccak(v)
        if t == "address":
            return (int(v, 16)).to_bytes(32, byteorder="big")
        if t.startswith("uint") or t.startswith("int"):
            return int(v).to_bytes(32, byteorder="big")
        if t == "bool":
            return (b"\x01" if v else b"\x00").rjust(32, b"\x00")
        # not supporting arrays or nested types in our use
        raise ValueError(f"Unsupported EIP-712 type: {t}")

    def encode_struct(type_name: str, data: Dict[str, Any]) -> bytes:
        fields = types[type_name]
        enc = [type_hash(type_name)]
        for f in fields:
            enc.append(encode_value(f["type"], data[f["name"]]))
        return keccak(abi_encode(["bytes32"] * len(enc), enc))

    domain_sep = encode_struct("EIP712Domain", domain)
    msg_hash = encode_struct(primary, message)

    digest = keccak(b"\x19\x01" + domain_sep + msg_hash)
    pk = bytes.fromhex(priv_hex)
    signature = _eth_keys.PrivateKey(pk).sign_msg_hash(digest)
    r = signature.r.to_bytes(32, "big").hex()
    s = signature.s.to_bytes(32, "big").hex()
    v = signature.v
    return "0x" + r + s + f"{v:02x}"


@dataclass
class OrderParams:
    token_id: str
    price: float
    size_shares: float
    side: str  # BUY or SELL
    expiration_unix: int
    fee_bps: str = "0"
    nonce: str = "0"


class PolyTradingClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        api_passphrase: str,
        signer_address: str,
        signer_private_key: str,
        funder_address: Optional[str] = None,
        signature_type: int = 0,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.api_passphrase = api_passphrase
        self.signer_address = self._normalize_addr(signer_address)
        self.signer_private_key = self._normalize_priv(signer_private_key)
        self.funder_address = self._normalize_addr(funder_address) if funder_address else self.signer_address
        self.signature_type = signature_type
        self.http = session or requests.Session()

        acct = Account.from_key(bytes.fromhex(self.signer_private_key))
        derived = acct.address.lower()
        if derived != self.signer_address:
            raise ValueError(
                f"Private key does not match signer address. Derived={derived}, Provided={self.signer_address}"
            )

    # ---- discovery helpers ----
    def fetch_exchange_address_for_token(self, token_id: str) -> Optional[str]:
        gamma = "https://gamma-api.polymarket.com"
        paths = [
            f"/markets?token_id={token_id}",
            f"/markets?tokenId={token_id}",
            f"/markets?ids={token_id}",
        ]
        for p in paths:
            try:
                r = self.http.get(gamma + p, timeout=15)
                if not r.ok:
                    continue
                data = r.json()
                # data may be an array of markets
                if isinstance(data, list) and data:
                    m = data[0]
                    ex = m.get("exchangeAddress") or m.get("exchange")
                    if isinstance(ex, str) and ex.startswith("0x") and len(ex) == 42:
                        return ex.lower()
            except Exception:
                continue
        return None

    def fetch_maker_nonce(self, maker_address: Optional[str] = None) -> Optional[str]:
        maker = maker_address or self.funder_address or self.signer_address
        paths = [
            f"/exchange/nonce?address={maker}",
            f"/nonce?address={maker}",
            f"/nonce?maker={maker}",
        ]
        for p in paths:
            # Try with L2 headers
            try:
                ts = str(int(time.time()))
                sig = self._l2_signature(ts, "GET", p)
                headers = {
                    "POLY_API_KEY": self.api_key,
                    "POLY_PASSPHRASE": self.api_passphrase,
                    "POLY_TIMESTAMP": ts,
                    "POLY_ADDRESS": self.signer_address,
                    "POLY_SIGNATURE": sig,
                }
                r = self.http.get(self.base_url + p, headers=headers, timeout=15)
                if r.ok:
                    print(f"[DISCOVERY] Nonce GET {p} -> {r.status_code} {r.text}")
                if r.ok:
                    jo = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                    val = jo.get("nonce") if isinstance(jo, dict) else None
                    if not val and isinstance(jo, dict):
                        res = jo.get("result")
                        if isinstance(res, dict):
                            val = res.get("nonce")
                    if val is None:
                        txt = r.text.strip()
                        if txt.isdigit():
                            val = txt
                    if val is not None:
                        return str(val)
            except Exception as ex:
                print(f"[DISCOVERY] Nonce GET {p} failed: {ex}")
            # Try without headers
            try:
                r = self.http.get(self.base_url + p, timeout=10)
                if r.ok:
                    print(f"[DISCOVERY] Nonce GET (noauth) {p} -> {r.status_code} {r.text}")
                if r.ok:
                    jo = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                    val = jo.get("nonce") if isinstance(jo, dict) else None
                    if val is None:
                        txt = r.text.strip()
                        if txt.isdigit():
                            val = txt
                    if val is not None:
                        return str(val)
            except Exception as ex:
                print(f"[DISCOVERY] Nonce GET (noauth) {p} failed: {ex}")
        return None

    @staticmethod
    def _normalize_addr(addr: Optional[str]) -> str:
        a = (addr or "").strip()
        if a.startswith("0X"):
            a = "0x" + a[2:]
        if not isinstance(a, str) or len(a) != 42 or not a.startswith("0x"):
            raise ValueError("Address must be a 0x-prefixed 40-hex-character string.")
        return a.lower()

    @staticmethod
    def _normalize_priv(pk: str) -> str:
        k = (pk or "").strip()
        if k.lower().startswith("0x"):
            k = k[2:]
        if len(k) != 64:
            raise ValueError("Private key must be 64 hex chars (optionally prefixed with 0x).")
        return k

    @staticmethod
    def _atomic(amount: float) -> int:
        return int(round(float(amount) * 1_000_000))

    @staticmethod
    def derive_api_credentials(
        signer_address: str, signer_private_key: str, clob_base_url: str = "https://clob.polymarket.com"
    ) -> Tuple[str, str, str]:
        signer_address = PolyTradingClient._normalize_addr(signer_address)
        signer_private_key = PolyTradingClient._normalize_priv(signer_private_key)

        acct = Account.from_key(bytes.fromhex(signer_private_key))
        derived = acct.address.lower()
        if derived != signer_address:
            raise ValueError(
                f"Private key does not match signer address. Derived={derived}, Provided={signer_address}"
            )

        ts = str(int(time.time()))
        typed = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                ],
                "ClobAuth": [
                    {"name": "address", "type": "address"},
                    {"name": "timestamp", "type": "string"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "message", "type": "string"},
                ],
            },
            "primaryType": "ClobAuth",
            "domain": {"name": "ClobAuthDomain", "version": "1", "chainId": 137},
            "message": {
                "address": signer_address,
                "timestamp": ts,
                "nonce": 0,
                "message": "This message attests that I control the given wallet",
            },
        }
        sig = _eip712_encode_and_sign(typed, signer_private_key)

        url = f"{clob_base_url}/auth/derive-api-key"
        headers = {
            "POLY_ADDRESS": signer_address,
            "POLY_SIGNATURE": sig,
            "POLY_TIMESTAMP": ts,
            "POLY_NONCE": "0",
        }
        r = requests.get(url, headers=headers, timeout=20)
        if not r.ok:
            raise RuntimeError(f"Failed to derive API key: {r.status_code} {r.text}")
        jo = r.json()
        api_key = jo.get("apiKey")
        secret = jo.get("secret")
        passphrase = jo.get("passphrase")
        if not api_key or not secret or not passphrase:
            raise RuntimeError("Derive API key succeeded but response missing fields.")
        return api_key, secret, passphrase

    def _l2_signature(self, ts_sec: str, method: str, path: str, body: str = "") -> str:
        prehash = f"{ts_sec}{method}{path}{body}"
        key_bytes = base64url_decode(self.api_secret)
        raw = hmac.new(key_bytes, prehash.encode("utf-8"), digestmod="sha256").digest()
        return base64url_encode(raw)

    def test_l2_auth(self) -> Tuple[int, str]:
        path = "/auth/api-keys"
        ts = str(int(time.time()))
        sig = self._l2_signature(ts, "GET", path)
        url = f"{self.base_url}{path}"
        headers = {
            "POLY_API_KEY": self.api_key,
            "POLY_PASSPHRASE": self.api_passphrase,
            "POLY_TIMESTAMP": ts,
            "POLY_ADDRESS": self.signer_address,
            "POLY_SIGNATURE": sig,
        }
        r = self.http.get(url, headers=headers, timeout=20)
        return r.status_code, r.text

    def build_signed_order(self, p: OrderParams, exchange_override: Optional[str] = None) -> Dict[str, Any]:
        px = max(0.0, min(1.0, float(p.price)))
        shares_atomic = self._atomic(p.size_shares)
        dollars_atomic = self._atomic(p.size_shares * px)

        if p.side.upper() == "BUY":
            maker_amount = str(dollars_atomic)
            taker_amount = str(shares_atomic)
            side_int = 0
        elif p.side.upper() == "SELL":
            maker_amount = str(shares_atomic)
            taker_amount = str(dollars_atomic)
            side_int = 1
        else:
            raise ValueError("side must be 'BUY' or 'SELL'")

        maker_addr = self.funder_address
        signer_addr = self.signer_address
        exchange = (exchange_override or EXCHANGE_ADDR).lower()

        salt_value = random.randint(100_000_000, 999_999_999)

        typed = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Order": [
                    {"name": "salt", "type": "uint256"},
                    {"name": "maker", "type": "address"},
                    {"name": "signer", "type": "address"},
                    {"name": "taker", "type": "address"},
                    {"name": "tokenId", "type": "uint256"},
                    {"name": "makerAmount", "type": "uint256"},
                    {"name": "takerAmount", "type": "uint256"},
                    {"name": "expiration", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "feeRateBps", "type": "uint256"},
                    {"name": "side", "type": "uint8"},
                    {"name": "exchangeAddr", "type": "address"},
                ],
            },
            "primaryType": "Order",
            "domain": {
                "name": "Polymarket Exchange",
                "version": "1",
                "chainId": 137,
                "verifyingContract": exchange,
            },
            "message": {
                "salt": salt_value,
                "maker": maker_addr,
                "signer": signer_addr,
                "taker": "0x0000000000000000000000000000000000000000",
                "tokenId": int(p.token_id),
                "makerAmount": int(maker_amount),
                "takerAmount": int(taker_amount),
                "expiration": int(p.expiration_unix),
                "nonce": int(p.nonce),
                "feeRateBps": int(p.fee_bps),
                "side": side_int,
                "exchangeAddr": exchange,
            },
        }
        sig = _eip712_encode_and_sign(typed, self.signer_private_key)

        if len(sig) == 132:
            v_hex = sig[130:132]
            v = int(v_hex, 16)
            if v >= 27:
                v -= 27
                sig = sig[:130] + f"{v:02x}"

        order = {
            "salt": str(salt_value),
            "maker": maker_addr,
            "signer": signer_addr,
            "taker": "0x0000000000000000000000000000000000000000",
            "tokenId": str(p.token_id),
            "makerAmount": str(maker_amount),
            "takerAmount": str(taker_amount),
            "expiration": str(p.expiration_unix),
            "nonce": str(p.nonce),
            "feeRateBps": str(p.fee_bps),
            "side": p.side.upper(),
            "signatureType": self.signature_type,
            "signature": sig,
        }
        return order

    def place_order(self, order: Dict[str, Any], order_type: str, client_id: Optional[str] = None) -> Tuple[int, str]:
        path = "/order"
        # Prepare side variants
        order_side_int = dict(order)
        try:
            side_val = order_side_int.get("side")
            order_side_int["side"] = 0 if str(side_val).upper() == "BUY" else 1 if str(side_val).upper() == "SELL" else side_val
        except Exception:
            pass

        # Prepare signature variants (std v=27/28 vs adjusted v=0/1)
        def adjust_v(sig_hex: str) -> str:
            if len(sig_hex) == 132:
                v_hex = sig_hex[130:132]
                v = int(v_hex, 16)
                if v >= 27:
                    v -= 27
                    return sig_hex[:130] + f"{v:02x}"
            return sig_hex

        order_sig_std = dict(order)
        order_sig_adj = dict(order)
        try:
            order_sig_adj["signature"] = adjust_v(order_sig_adj.get("signature", ""))
        except Exception:
            pass

        # Log preferred variant for debugging
        preferred_body = {"order": order_sig_std, "owner": self.api_key, "orderType": order_type}
        if client_id:
            preferred_body["client_id"] = client_id
        preferred_body_str = json.dumps(preferred_body, separators=(",", ":"))
        try:
            sig_hex = order_sig_std.get("signature", "")
            v_hex = sig_hex[130:132] if len(sig_hex) == 132 else ""
            print("[DEBUG] Preferred order payload:")
            print("[DEBUG]   side:", order_sig_std.get("side"), "signatureType:", order_sig_std.get("signatureType"))
            print("[DEBUG]   maker:", order_sig_std.get("maker"), "signer:", order_sig_std.get("signer"))
            print("[DEBUG]   tokenId:", order_sig_std.get("tokenId"))
            print("[DEBUG]   makerAmount:", order_sig_std.get("makerAmount"), "takerAmount:", order_sig_std.get("takerAmount"))
            print("[DEBUG]   expiration:", order_sig_std.get("expiration"), "nonce:", order_sig_std.get("nonce"), "feeRateBps:", order_sig_std.get("feeRateBps"))
            print("[DEBUG]   signature len:", len(sig_hex), "v:", v_hex)
            print("[DEBUG]   HTTP body:", preferred_body_str)
        except Exception:
            pass

        bodies = []
        bodies.append(("A", preferred_body))
        bodies.append(("B", {"order": dict(order_side_int, signature=order_sig_std.get("signature")), "owner": self.api_key, "orderType": order_type, **({"client_id": client_id} if client_id else {})}))
        bodies.append(("C", {"order": order_sig_std, "owner": self.signer_address, "orderType": order_type, **({"client_id": client_id} if client_id else {})}))
        bodies.append(("D", {"order": dict(order_side_int, signature=order_sig_std.get("signature")), "owner": self.signer_address, "orderType": order_type, **({"client_id": client_id} if client_id else {})}))
        bodies.append(("E", {"order": order_sig_adj, "owner": self.api_key, "orderType": order_type, **({"client_id": client_id} if client_id else {})}))
        bodies.append(("F", {"order": dict(order_side_int, signature=order_sig_adj.get("signature")), "owner": self.api_key, "orderType": order_type, **({"client_id": client_id} if client_id else {})}))
        bodies.append(("G", {"order": order_sig_adj, "owner": self.signer_address, "orderType": order_type, **({"client_id": client_id} if client_id else {})}))
        bodies.append(("H", {"order": dict(order_side_int, signature=order_sig_adj.get("signature")), "owner": self.signer_address, "orderType": order_type, **({"client_id": client_id} if client_id else {})}))

        last_status, last_text = 0, ""
        for label, body in bodies:
            body_str = json.dumps(body, separators=(",", ":"))

            ts = str(int(time.time()))
            sig = self._l2_signature(ts, "POST", path, body_str)

            url = f"{self.base_url}{path}"
            headers = {
                "POLY_API_KEY": self.api_key,
                "POLY_PASSPHRASE": self.api_passphrase,
                "POLY_TIMESTAMP": ts,
                "POLY_ADDRESS": self.signer_address,
                "POLY_SIGNATURE": sig,
                "Content-Type": "application/json",
            }
            try:
                r = self.http.post(url, headers=headers, data=body_str, timeout=30)
                last_status, last_text = r.status_code, r.text
                if r.ok:
                    print(f"[DEBUG] Variant {label} accepted")
                    return last_status, last_text
                else:
                    print(f"[DEBUG] Variant {label} -> {r.status_code} {r.text}")
            except Exception as ex:
                last_status, last_text = 0, f"Exception on variant {label}: {ex}"
                print(last_text)
        return last_status, last_text

    def cancel_order(self, order_id: Optional[str] = None, client_id: Optional[str] = None) -> Tuple[int, str]:
        path = "/order/cancel"
        payloads = []
        if order_id:
            payloads.append({"orderId": order_id, "owner": self.api_key})
            payloads.append({"order_id": order_id, "owner": self.api_key})
        if client_id:
            payloads.append({"client_id": client_id, "owner": self.api_key})

        last_status, last_text = 0, ""
        for body in payloads or [{"owner": self.api_key}]:
            body_str = json.dumps(body, separators=(",", ":"))
            ts = str(int(time.time()))
            sig = self._l2_signature(ts, "POST", path, body_str)
            url = f"{self.base_url}{path}"
            headers = {
                "POLY_API_KEY": self.api_key,
                "POLY_PASSPHRASE": self.api_passphrase,
                "POLY_TIMESTAMP": ts,
                "POLY_ADDRESS": self.signer_address,
                "POLY_SIGNATURE": sig,
                "Content-Type": "application/json",
            }
            r = self.http.post(url, headers=headers, data=body_str, timeout=20)
            last_status, last_text = r.status_code, r.text
            if r.ok:
                break
        return last_status, last_text

    def get_order_status(self, order_id: str) -> Tuple[int, str]:
        ts = str(int(time.time()))
        path = f"/order/{order_id}"
        sig = self._l2_signature(ts, "GET", path)
        headers = {
            "POLY_API_KEY": self.api_key,
            "POLY_PASSPHRASE": self.api_passphrase,
            "POLY_TIMESTAMP": ts,
            "POLY_ADDRESS": self.signer_address,
            "POLY_SIGNATURE": sig,
        }
        url = f"{self.base_url}{path}"
        r = self.http.get(url, headers=headers, timeout=20)
        if r.status_code != 404:
            return r.status_code, r.text

        path = f"/orders?ids={order_id}"
        ts = str(int(time.time()))
        sig = self._l2_signature(ts, "GET", path)
        headers["POLY_TIMESTAMP"] = ts
        headers["POLY_SIGNATURE"] = sig
        url = f"{self.base_url}{path}"
        r = self.http.get(url, headers=headers, timeout=20)
        return r.status_code, r.text
