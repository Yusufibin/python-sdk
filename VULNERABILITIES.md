# Vulnerability Report: Lightspark Python SDK

The following vulnerabilities and security weaknesses were identified during a manual code audit of the Lightspark Python SDK.

## 1. Hash Collision in UMA Identifier Hashing (High)
**File:** `lightspark/lightspark_client.py`
**Method:** `hash_uma_identifier(self, identifier: str, signing_private_key: bytes)`

**Description:**
The method concatenates the `identifier` and a date string (`month-year`) without a delimiter before hashing.
```python
input_data = identifier + f"{now.month}-{now.year}" + signing_private_key.hex()
```
This leads to hash collisions because the boundary between the identifier and the month is ambiguous.

**Impact:**
An attacker could potentially craft an identifier that, when combined with a different date, results in the same hash as a target user's identifier. This could lead to account impersonation or data cross-talk if the hash is used as a primary key or for authorization.

**Proof of Concept:**
- User A: identifier="alice", month=11, year=2024 -> "alice11-2024"
- User B: identifier="alice1", month=1, year=2024 -> "alice11-2024"
Both result in the same SHA256 hash.

**Recommendation:**
Use a non-alphanumeric delimiter between components (e.g., `|` or `:`) or use a structured serialization format like JSON.

---

## 2. Unhandled Exceptions in Webhook Parsing (Medium / DoS)
**File:** `lightspark/webhooks.py`
**Methods:** `parse(cls, data: bytes)` and `verify_and_parse(cls, data: bytes, hex_digest: str, webhook_secret: str)`

**Description:**
The `parse` method directly accesses the `WebhookEventType` enum using a key from the JSON payload:
```python
event_type=WebhookEventType[event["event_type"]]
```
If `event_type` is missing or contains an invalid value, it raises a `KeyError`. Similarly, `datetime.fromisoformat(event["timestamp"])` raises a `ValueError` for invalid dates, and `bytes.fromhex(hex_digest)` raises a `ValueError` for non-hex strings.

**Impact:**
An attacker can send a malformed webhook request to the application's webhook endpoint, causing the SDK to raise an unhandled exception. If the host application (like the example Flask server) does not wrap the SDK call in a try-except block, the entire process/request-handler will crash, leading to a Denial of Service.

**Recommendation:**
The SDK should catch these exceptions internally and raise a specific, documented `LightsparkException` or return an error state, allowing the user to handle it gracefully without crashing.

---

## 3. Weak PBKDF2 Iterations in Legacy Cipher (Medium)
**File:** `lightspark/utils/crypto.py`
**Method:** `decrypt_private_key`

**Description:**
The SDK supports a legacy cipher version `AES_256_CBC_PBKDF2_5000_SHA256` which uses only 5,000 PBKDF2 iterations.
```python
if cipher_version == "AES_256_CBC_PBKDF2_5000_SHA256":
    header = {"v": 0, "i": 5000}
```
Modern standards (e.g., OWASP) recommend at least 600,000 iterations for PBKDF2-HMAC-SHA256. 5,000 iterations offer very little protection against modern offline brute-force attacks.

**Recommendation:**
Deprecate the legacy version and encourage users to migrate to the current version (which uses 500,000 iterations, though even this could be increased).

---

## 4. Sensitive Information Leakage in Logs (Low)
**File:** `lightspark/requests/requester.py`
**Method:** `execute_graphql`

**Description:**
The `Requester` logs the entire GraphQL payload, including all variables, at the `DEBUG` level:
```python
logger.debug("Sending request to GraphQL with query = %s, payload = %s}", query, payload)
```

**Impact:**
If an application is running with debug logging enabled (common in development and sometimes accidentally in production), sensitive information such as payment hashes, node IDs, and potentially even keys (if passed as variables) will be written to plain-text log files.

**Recommendation:**
Sanitize the payload before logging or avoid logging the full payload at any level.

---

## 5. Insecure Phone Number Hashing (Low)
**File:** `lightspark/lightspark_client.py`
**Method:** `_hash_phone_number(self, phone_number_e164_format: str)`

**Description:**
The method uses a plain SHA256 hash of the phone number:
```python
return sha256(phone_number_e164_format.encode()).hexdigest()
```

**Impact:**
Phone numbers have very low entropy (especially within a known region). A plain SHA256 hash is trivial to reverse using a rainbow table or brute-force attack. This provides a false sense of privacy for user phone numbers.

**Recommendation:**
Use a salted hash or a dedicated password hashing algorithm like Argon2 with a global pepper if the goal is to anonymize the data while remaining deterministic.
