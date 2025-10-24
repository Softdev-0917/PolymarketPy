Option Strict On
Option Infer On

Imports System.IO
Imports System.Net.Http
Imports System.Security.Cryptography
Imports System.Text
Imports System.Linq
Imports System.Threading
Imports Newtonsoft.Json
Imports Newtonsoft.Json.Linq
Imports Nethereum.Signer
Imports Nethereum.Signer.EIP712

Public Class PolyTradingApi
    Private ReadOnly _baseUrl As String
    Private ReadOnly _apiKey As String                ' L2 key (uuid)
    Private ReadOnly _apiSecret As String             ' L2 secret (base64url)
    Private ReadOnly _apiPassphrase As String
    Private ReadOnly _signerAddress As String         ' 0x... (signs EIP-712 orders)
    Private ReadOnly _signerPrivateKey As String      ' 64-hex (no 0x)
    Private ReadOnly _funderAddress As String         ' maker/funder (== signer for EOA; proxy for Email/Browser wallet)
    Private ReadOnly _signatureType As Integer        ' 0=EOA, 1=POLY_PROXY, 2=POLY_GNOSIS_SAFE

    ' ---- server time offset cache (seconds) ----
    Private Shared _offsetSec As Long = 0
    Private Shared _lastSyncUtc As DateTime = DateTime.MinValue
    Private Shared _offsetLock As New Object()
    
    ' Exchange contract address (Polygon mainnet)
    ' NOTE: This is the current Polymarket exchange contract as of Oct 2025
    ' If markets migrate to a new contract, this may need updating
    ' Verify via Gamma API /markets response field "exchangeAddress"
    Private Const EXCHANGE_ADDR As String = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"

    Public Sub New(baseUrl As String,
                   apiKey As String,
                   apiSecret As String,
                   apiPassphrase As String,
                   signerAddress As String,
                   signerPrivateKey As String,
                   Optional funderAddress As String = Nothing,
                   Optional signatureType As Integer = 0)

        _baseUrl = If(String.IsNullOrWhiteSpace(baseUrl), "https://clob.polymarket.com", baseUrl.TrimEnd("/"c))
        _apiKey = apiKey
        _apiSecret = apiSecret
        _apiPassphrase = apiPassphrase
        _signerAddress = NormalizeHexAddress(signerAddress)
        _signerPrivateKey = NormalizePrivKey(signerPrivateKey)
        _signatureType = signatureType
        _funderAddress = If(String.IsNullOrWhiteSpace(funderAddress), _signerAddress, NormalizeHexAddress(funderAddress))
        
        ' Debug: Show what addresses are actually set
        Console.WriteLine($"[INIT] Signer Address: {_signerAddress}")
        Console.WriteLine($"[INIT] Funder Address: {_funderAddress}")
        Console.WriteLine($"[INIT] Signature Type: {_signatureType}")
        Console.WriteLine($"[INIT] Addresses Match: {_signerAddress.Equals(_funderAddress, StringComparison.OrdinalIgnoreCase)}")

        ' sanity: address must match private key
        Dim pk As New EthECKey(_signerPrivateKey)
        Dim derived = pk.GetPublicAddress()
        If Not String.Equals(_signerAddress.ToLowerInvariant(), derived.ToLowerInvariant(), StringComparison.Ordinal) Then
            Throw New ArgumentException($"Private key does not match signer address. Derived={derived}, Provided={_signerAddress}")
        End If
    End Sub

    ' =================== Server time sync (seconds) ===================
    Private Async Function SyncServerTimeAsync() As Task
        Dim serverSec As Long
        Using hc As New HttpClient()
            hc.BaseAddress = New Uri(_baseUrl)
            hc.Timeout = TimeSpan.FromSeconds(2)
            Dim r = Await hc.GetAsync("/time").ConfigureAwait(False)
            Dim s = (Await r.Content.ReadAsStringAsync().ConfigureAwait(False)).Trim()

            ' Accept either plain integer (e.g., "1728870904") or JSON {"time": 1728870904}
            If Not Long.TryParse(s, serverSec) Then
                Dim jo As JObject = JObject.Parse(s)
                serverSec = CLng(jo("time")?.ToString())
            End If
        End Using

        Dim localSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        SyncLock _offsetLock
            _offsetSec = serverSec - localSec
            _lastSyncUtc = DateTime.UtcNow
        End SyncLock
    End Function

    ' Use server-aligned seconds, but stay 1s behind to avoid being in the future
    Private Function NowServerSecBounded() As String
        Dim needSync As Boolean = False
        SyncLock _offsetLock
            ' refresh every 30 seconds (was 3 minutes)
            If (DateTime.UtcNow - _lastSyncUtc) > TimeSpan.FromSeconds(30) Then
                needSync = True
            End If
        End SyncLock
        If needSync Then
            SyncServerTimeAsync().GetAwaiter().GetResult()
        End If

        Dim localSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        Dim off As Long
        SyncLock _offsetLock
            off = _offsetSec
        End SyncLock

        ' stay safely inside the server window
        Dim ts As Long = (localSec + off) - 2   ' << was -1
        Return ts.ToString()
    End Function

    Private Sub ForceResync()
        SyncServerTimeAsync().GetAwaiter().GetResult()
    End Sub

    ' ================= L1: DERIVE API CREDENTIALS (EIP-712 typed-data) =================
    Public Shared Function DeriveApiCredentials(signerAddress As String,
                                                signerPrivateKey As String,
                                                Optional clobBaseUrl As String = "https://clob.polymarket.com") _
                                                As (apiKey As String, secret As String, passphrase As String)

        Dim addrOrig As String = (If(signerAddress, String.Empty)).Trim()
        If Not System.Text.RegularExpressions.Regex.IsMatch(addrOrig, "^0x[0-9a-fA-F]{40}$") Then
            Throw New ArgumentException("Address must be a 0x-prefixed 40-hex-character string.")
        End If
        Dim addrLower = NormalizeHexAddress(signerAddress)
        Dim pkHex = NormalizePrivKey(signerPrivateKey)
        Dim key = New EthECKey(pkHex)
        Dim derived = key.GetPublicAddress()
        If Not String.Equals(addrLower.ToLowerInvariant(), derived.ToLowerInvariant(), StringComparison.Ordinal) Then
            Throw New ArgumentException($"Private key does not match signer address. Derived={derived}, Provided={addrOrig}")
        End If

        ' Use local unix timestamp seconds (official clients do this)
        Dim ts As String = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()

        Dim nonceStr As String = "0"
        Dim attestationMsg As String = "This message attests that I control the given wallet"

        Dim typedDataJson As String =
$"{{
  ""types"": {{
    ""EIP712Domain"": [
      {{ ""name"": ""name"", ""type"": ""string"" }},
      {{ ""name"": ""version"", ""type"": ""string"" }},
      {{ ""name"": ""chainId"", ""type"": ""uint256"" }}
    ],
    ""ClobAuth"": [
      {{ ""name"": ""address"", ""type"": ""address"" }},
      {{ ""name"": ""timestamp"", ""type"": ""string"" }},
      {{ ""name"": ""nonce"", ""type"": ""uint256"" }},
      {{ ""name"": ""message"", ""type"": ""string"" }}
    ]
  }},
  ""primaryType"": ""ClobAuth"",
  ""domain"": {{
    ""name"": ""ClobAuthDomain"",
    ""version"": ""1"",
    ""chainId"": 137
  }},
  ""message"": {{
    ""address"": ""{addrOrig}"",
    ""timestamp"": ""{ts}"",
    ""nonce"": {nonceStr},
    ""message"": ""{attestationMsg}""
  }}
}}"

        Dim typedDataJsonClean As String = typedDataJson.Replace("\r", String.Empty).Replace("\n", String.Empty)
        Dim signer = New Eip712TypedDataSigner()
        Dim signature As String = signer.SignTypedDataV4(typedDataJsonClean, key)
        ' --- TEMP DEBUG LOGS ---
        Console.ForegroundColor = ConsoleColor.DarkCyan
        Console.WriteLine("[DBG] Derive typedDataJson:")
        Console.ResetColor()
        Console.WriteLine(typedDataJsonClean)
        Console.WriteLine($"[DBG] Headers -> POLY_ADDRESS={addrOrig}, POLY_TIMESTAMP={ts}, POLY_NONCE={nonceStr}")
        Console.WriteLine($"[DBG] Signature (len={signature.Length}): {signature}")

        Using client As New HttpClient()
            client.BaseAddress = New Uri(clobBaseUrl)

            ' Single attempt: GET without query, headers carry nonce/timestamp
            Dim derivePath As String = "/auth/derive-api-key"
            Dim req = New HttpRequestMessage(HttpMethod.Get, derivePath)
            req.Headers.Add("POLY_ADDRESS", addrOrig)
            req.Headers.Add("POLY_SIGNATURE", signature)
            req.Headers.Add("POLY_TIMESTAMP", ts)     ' seconds
            req.Headers.Add("POLY_NONCE", nonceStr)
            Console.WriteLine($"[DBG] Derive URL={client.BaseAddress}{derivePath}")
            Dim resp = client.SendAsync(req).GetAwaiter().GetResult()
            Dim body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Console.WriteLine($"[DBG] Derive status={(CInt(resp.StatusCode))} body={body}")
            If Not resp.IsSuccessStatusCode Then Throw New Exception($"Failed to derive API key: {body}")

            Dim jo = JObject.Parse(body)
            Dim apiKey = jo("apiKey")?.ToString()
            Dim secret = jo("secret")?.ToString()
            Dim passphrase = jo("passphrase")?.ToString()
            If String.IsNullOrWhiteSpace(apiKey) OrElse String.IsNullOrWhiteSpace(secret) OrElse String.IsNullOrWhiteSpace(passphrase) Then
                Throw New Exception("Derive API key succeeded but response missing fields.")
            End If
            Return (apiKey, secret, passphrase)
        End Using
    End Function

    ' ================= L2: AUTH SANITY (seconds + Base64 HMAC) =================
    Public Async Function TestL2AuthAsync(Optional forceResyncFirst As Boolean = False) As Task(Of (status As Integer, body As String))
        Dim path As String = "/auth/api-keys"

        If forceResyncFirst Then
            ForceResync()
        End If

        ' Add small delay to ensure we're not hitting rate limits
        Await Task.Delay(500).ConfigureAwait(False)

        ' Use local unix seconds for L2 to match official client
        Dim tsSec As String = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
        Console.WriteLine($"[DBG] L2 ts={tsSec}")

        ' prehash = timestamp(sec) + METHOD + path + body("")
        Dim prehash As String = tsSec & "GET" & path
        Dim keyBytes As Byte() = Base64UrlDecodeStrict(_apiSecret) ' should be 32 bytes
        Dim sig As String
        Using h As New HMACSHA256(keyBytes)
            Dim raw = h.ComputeHash(Encoding.UTF8.GetBytes(prehash))
            sig = Base64UrlEncode(raw)
        End Using

        Console.WriteLine($"[DBG] === L2 AUTH (WORKING) HMAC DETAILS ===")
        Console.WriteLine($"[DBG] L2 Auth - API Key: {_apiKey.Substring(0, 8)}***")
        Console.WriteLine($"[DBG] L2 Auth - Address: {_signerAddress}")
        Console.WriteLine($"[DBG] L2 Auth - Timestamp: {tsSec}")
        Console.WriteLine($"[DBG] L2 Auth - Method: GET")
        Console.WriteLine($"[DBG] L2 Auth - Path: {path}")
        Console.WriteLine($"[DBG] L2 Auth - Body: (empty)")
        Console.WriteLine($"[DBG] L2 Auth - Prehash: {prehash}")
        Console.WriteLine($"[DBG] L2 Auth - Secret (first 16): {_apiSecret.Substring(0, Math.Min(16, _apiSecret.Length))}***")
        Console.WriteLine($"[DBG] L2 Auth - Signature: {sig}")
        Console.WriteLine($"[DBG] L2 Auth - Encoding: Base64URL")
        Console.WriteLine($"[DBG] =========================================")

        Using client As New HttpClient()
            client.BaseAddress = New Uri(_baseUrl)
            client.Timeout = TimeSpan.FromSeconds(30) ' Increase timeout
            
            Dim req = New HttpRequestMessage(HttpMethod.[Get], path)
            req.Headers.Add("POLY_API_KEY", _apiKey)
            req.Headers.Add("POLY_PASSPHRASE", _apiPassphrase)
            req.Headers.Add("POLY_TIMESTAMP", tsSec)                 ' seconds (bounded)
            req.Headers.Add("POLY_ADDRESS", _signerAddress)
            req.Headers.Add("POLY_SIGNATURE", sig)                   ' Base64

            Try
                Dim resp = Await client.SendAsync(req).ConfigureAwait(False)
                Dim body = Await resp.Content.ReadAsStringAsync().ConfigureAwait(False)
                
                Console.WriteLine($"[DBG] L2 Auth Response: {CInt(resp.StatusCode)} - {body}")
                
                Return (CInt(resp.StatusCode), body)
            Catch ex As Exception
                Console.WriteLine($"[DBG] L2 Auth Exception: {ex.Message}")
                Return (0, $"Exception: {ex.Message}")
            End Try
        End Using
    End Function

    ' ================= Build + sign order (EIP-712) =================
    ' side: 0 = BUY (maker pays USDC), 1 = SELL (maker pays shares)
    Public Function BuildSignedOrder(tokenId As String,
                                     price As Decimal,
                                     sizeShares As Decimal,
                                     side As Integer,
                                     expirationUnix As Long,
                                     Optional feeBps As String = "0",
                                     Optional nonce As String = "0") As JObject

        If side <> 0 AndAlso side <> 1 Then Throw New ArgumentException("side must be 0 (BUY) or 1 (SELL)")
        Dim px As Decimal = Math.Max(0D, Math.Min(1D, price))
        Dim sharesAtomic As Decimal = Math.Round(sizeShares * 1_000_000D, 0, MidpointRounding.AwayFromZero)
        If sharesAtomic <= 0D Then Throw New ArgumentException("sizeShares must be > 0")
        Dim dollarsAtomic As Decimal = Math.Round(sizeShares * px * 1_000_000D, 0, MidpointRounding.AwayFromZero)

        Dim makerAmount As String, takerAmount As String
        If side = 0 Then
            ' BUY: pay USDC, receive shares
            makerAmount = CDec(dollarsAtomic).ToString(Globalization.CultureInfo.InvariantCulture)
            takerAmount = CDec(sharesAtomic).ToString(Globalization.CultureInfo.InvariantCulture)
        Else
            ' SELL: pay shares, receive USDC
            makerAmount = CDec(sharesAtomic).ToString(Globalization.CultureInfo.InvariantCulture)
            takerAmount = CDec(dollarsAtomic).ToString(Globalization.CultureInfo.InvariantCulture)
        End If

        ' CRITICAL FIX: Use lowercase addresses for EIP-712 consistency
        ' Polymarket expects lowercase addresses throughout (both EIP-712 and JSON)
        Dim makerAddr As String = _funderAddress.ToLowerInvariant()      ' Lowercase for consistency
        Dim signerAddr As String = _signerAddress.ToLowerInvariant()     ' Lowercase for consistency  
        Dim exchange As String = EXCHANGE_ADDR.ToLowerInvariant()        ' Lowercase for consistency

        ' Use small integer salt like Python (not huge uint256)
        ' Framework 4.8 compatible version
        Dim rnd As New Random()
        Dim saltValue As Long = CLng(rnd.Next(100000000, 1000000000))

        ' MICHAEL'S FIX: EIP-712 typed data with NUMERIC fields as raw numbers (no quotes)
        ' This is CRITICAL - the EIP-712 signature must use raw numbers, not strings
        Dim typedJson As String =
$"{{
  ""types"": {{
    ""EIP712Domain"": [
      {{ ""name"": ""name"", ""type"": ""string"" }},
      {{ ""name"": ""version"", ""type"": ""string"" }},
      {{ ""name"": ""chainId"", ""type"": ""uint256"" }},
      {{ ""name"": ""verifyingContract"", ""type"": ""address"" }}
    ],
    ""Order"": [
      {{ ""name"": ""salt"", ""type"": ""uint256"" }},
      {{ ""name"": ""maker"", ""type"": ""address"" }},
      {{ ""name"": ""signer"", ""type"": ""address"" }},
      {{ ""name"": ""taker"", ""type"": ""address"" }},
      {{ ""name"": ""tokenId"", ""type"": ""uint256"" }},
      {{ ""name"": ""makerAmount"", ""type"": ""uint256"" }},
      {{ ""name"": ""takerAmount"", ""type"": ""uint256"" }},
      {{ ""name"": ""expiration"", ""type"": ""uint256"" }},
      {{ ""name"": ""nonce"", ""type"": ""uint256"" }},
      {{ ""name"": ""feeRateBps"", ""type"": ""uint256"" }},
      {{ ""name"": ""side"", ""type"": ""uint8"" }},
      {{ ""name"": ""exchangeAddr"", ""type"": ""address"" }}
    ]
  }},
  ""primaryType"": ""Order"",
  ""domain"": {{
    ""name"": ""Polymarket Exchange"",
    ""version"": ""1"",
    ""chainId"": 137,
    ""verifyingContract"": ""{exchange}""
  }},
  ""message"": {{
    ""salt"": {saltValue.ToString(System.Globalization.CultureInfo.InvariantCulture)},
    ""maker"": ""{makerAddr}"",
    ""signer"": ""{signerAddr}"",
    ""taker"": ""0x0000000000000000000000000000000000000000"",
    ""tokenId"": {tokenId},
    ""makerAmount"": {makerAmount},
    ""takerAmount"": {takerAmount},
    ""expiration"": {expirationUnix},
    ""nonce"": {nonce},
    ""feeRateBps"": {feeBps},
    ""side"": {side},
    ""exchangeAddr"": ""{exchange}""
  }}
}}"

        Console.WriteLine("[DBG] EIP-712 typedJson for signing:")
        Console.WriteLine(typedJson)
        Console.WriteLine()
        
        ' CRITICAL FIX: Ensure proper signature format and recovery
        Dim key = New EthECKey(_signerPrivateKey)
        Dim signer = New Eip712TypedDataSigner()
        Dim sigHex As String = signer.SignTypedDataV4(typedJson, key)   ' "0x..."
        
        ' Ensure signature is properly formatted (65 bytes = 130 hex chars + 0x)
        If sigHex.Length <> 132 Then
            Console.WriteLine($"[WARN] Signature length unexpected: {sigHex.Length}, expected 132")
        End If
        
        ' CRITICAL FIX: Try signature recovery ID adjustment for Polymarket compatibility
        Console.WriteLine($"[DBG] Original EIP-712 signature: {sigHex}")
        Console.WriteLine($"[DBG] Signature length: {sigHex.Length}")
        
        ' Validate signature format
        If sigHex.Length <> 132 Then
            Throw New InvalidOperationException($"Invalid signature length: {sigHex.Length}, expected 132")
        End If
        
        ' Try adjusting recovery ID (common EIP-712 compatibility issue)
        If sigHex.Length = 132 Then
            Dim lastByte As String = sigHex.Substring(130, 2)
            Dim recoveryId As Integer = Convert.ToInt32(lastByte, 16)
            
            ' Polymarket might expect recovery ID in range 0-3 instead of 27-30
            If recoveryId >= 27 Then
                recoveryId -= 27
                Dim adjustedSig As String = sigHex.Substring(0, 130) & recoveryId.ToString("x2")
                Console.WriteLine($"[DBG] Adjusted signature (recovery ID {recoveryId}): {adjustedSig}")
                sigHex = adjustedSig
            End If
        End If

        ' Build order payload for POST /order
        ' CRITICAL: Polymarket CLOB API expects ALL numeric fields as STRINGS in the JSON payload
        ' Even though EIP-712 signing uses numbers, the final HTTP POST must use strings
        ' 🚀 OFFICIAL POLYMARKET DOCS: Use "BUY"/"SELL" strings (NOT "0"/"1")
        Dim sideStr As String = If(side = 0, "BUY", "SELL")
        Console.WriteLine($"🚀 [OFFICIAL DOCS] USING BUY/SELL FORMAT - Side value: {side} -> '{sideStr}'")
        
        Dim order As New JObject From {
            {"salt", saltValue.ToString(System.Globalization.CultureInfo.InvariantCulture)},  ' STRING with InvariantCulture to avoid scientific notation
            {"maker", makerAddr},                                       ' Already lowercase
            {"signer", signerAddr},                                     ' Already lowercase
            {"taker", "0x0000000000000000000000000000000000000000"},
            {"tokenId", tokenId},                                       ' Already string
            {"makerAmount", makerAmount},                               ' Already string
            {"takerAmount", takerAmount},                               ' Already string
            {"expiration", expirationUnix.ToString()},
            {"nonce", nonce},                                           ' Already string
            {"feeRateBps", feeBps},                                     ' Already string
            {"side", sideStr},                                          ' STRING "BUY"/"SELL" as per official docs!
            {"signatureType", _signatureType},                          ' INTEGER like Michael's example
            {"signature", sigHex}
        }

        Return order
    End Function

    ' ================= L2: PLACE ORDER (single-shot; seconds timestamp + Base64 HMAC) =================
    Public Async Function PlaceOrderAsync(order As JObject,
                                          orderType As String,
                                          Optional clientId As String = Nothing) _
                                          As Task(Of (status As Integer, body As String))

        Dim path As String = "/order"
        
        ' Add delay to avoid rate limiting and ensure proper timing
        Await Task.Delay(1000).ConfigureAwait(False)
        
        ' Serialize order first to get the exact JSON string
        Dim orderStr As String = order.ToString(Newtonsoft.Json.Formatting.None)
        
        Dim bodyJo As New JObject From {
            {"order", order},
            {"owner", _apiKey},  ' owner is API key - CRITICAL: this must match the API key used for HMAC
            {"orderType", orderType}
        }
        If Not String.IsNullOrEmpty(clientId) Then bodyJo("client_id") = clientId

        Dim bodyStr As String = bodyJo.ToString(Newtonsoft.Json.Formatting.None)

        ' DEBUG: Log the complete request body
        Console.WriteLine("[DEBUG] ===== PLACE ORDER REQUEST =====")
        Console.WriteLine($"[DEBUG] Path: {path}")
        Console.WriteLine($"[DEBUG] Body: {bodyStr}")
        Console.WriteLine($"[DEBUG] Order (standalone): {orderStr}")
        Console.WriteLine()

        ' Use local timestamp like working L2 auth (CRITICAL FIX)
        Dim tsSec As String = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
        Dim prehash As String = tsSec & "POST" & path & bodyStr

        ' Persist inputs for Python helper parity check
        Try
            Dim cwd As String = Directory.GetCurrentDirectory()
            Dim helperDir As String = IO.Path.Combine(cwd, "py-derive-check")
            If Not Directory.Exists(helperDir) Then Directory.CreateDirectory(helperDir)
            File.WriteAllText(IO.Path.Combine(helperDir, "body.json"), bodyStr, Encoding.UTF8)
            File.WriteAllText(IO.Path.Combine(helperDir, "timestamp.txt"), tsSec, Encoding.UTF8)
            ' Store current derived secret for convenience
            If Not String.IsNullOrEmpty(_apiSecret) Then
                File.WriteAllText(IO.Path.Combine(helperDir, "secret.txt"), _apiSecret, Encoding.UTF8)
            End If
        Catch __ As Exception
            ' noop: helper files are best-effort
        End Try

        ' API secret is Base64URL encoded, decode it
        Dim keyBytes As Byte() = Base64UrlDecodeStrict(_apiSecret)

        ' Use Base64URL encoding like working L2 auth (CRITICAL FIX)
        Dim sig As String
        Using h As New HMACSHA256(keyBytes)
            Dim raw = h.ComputeHash(Encoding.UTF8.GetBytes(prehash))
            sig = Base64UrlEncode(raw)  ' Base64URL like working L2 auth
        End Using

        Console.WriteLine($"[DEBUG] === ORDER PLACEMENT (FAILING) HMAC DETAILS ===")
        Console.WriteLine($"[DEBUG] Order - API Key: {_apiKey.Substring(0, 8)}***")
        Console.WriteLine($"[DEBUG] Order - Address: {_signerAddress}")
        Console.WriteLine($"[DEBUG] Order - Timestamp: {tsSec}")
        Console.WriteLine($"[DEBUG] Order - Method: POST")
        Console.WriteLine($"[DEBUG] Order - Path: {path}")
        Console.WriteLine($"[DEBUG] Order - Body length: {bodyStr.Length}")
        Console.WriteLine($"[DEBUG] Order - Prehash: {prehash}")
        Console.WriteLine($"[DEBUG] Order - Secret (first 16): {_apiSecret.Substring(0, Math.Min(16, _apiSecret.Length))}***")
        Console.WriteLine($"[DEBUG] Order - Signature: {sig}")
        Console.WriteLine($"[DEBUG] Order - Encoding: Base64URL")
        Console.WriteLine($"[DEBUG] Order - Key length: {keyBytes.Length} bytes")
        Console.WriteLine($"[DEBUG] ==============================================")
        
        ' Also save prehash for debugging
        Try
            Dim helperDir As String = IO.Path.Combine(Directory.GetCurrentDirectory(), "py-derive-check")
            File.WriteAllText(IO.Path.Combine(helperDir, "prehash.txt"), prehash, Encoding.UTF8)
        Catch
        End Try

        Console.WriteLine($"[DEBUG] Request Headers:")
        Console.WriteLine($"[DEBUG]   POLY_API_KEY: {_apiKey}")
        Console.WriteLine($"[DEBUG]   POLY_PASSPHRASE: {_apiPassphrase}")
        Console.WriteLine($"[DEBUG]   POLY_TIMESTAMP: {tsSec}")
        Console.WriteLine($"[DEBUG]   POLY_ADDRESS: {_signerAddress}")
        Console.WriteLine($"[DEBUG]   POLY_SIGNATURE: {sig}")
        Console.WriteLine($"[DEBUG]   Content-Type: application/json")
        Console.WriteLine("[DEBUG] ================================")
        Console.WriteLine()

        Using client As New HttpClient()
            client.BaseAddress = New Uri(_baseUrl)
            client.Timeout = TimeSpan.FromSeconds(30) ' Increase timeout
            
            Dim req = New HttpRequestMessage(HttpMethod.Post, path)
            req.Content = New StringContent(bodyStr, Encoding.UTF8, "application/json")
            ' L2 Authentication (API Key HMAC) required for /order endpoint per docs
            
            ' L2 Authentication (API Key)
            req.Headers.Add("POLY_API_KEY", _apiKey)
            req.Headers.Add("POLY_PASSPHRASE", _apiPassphrase)
            req.Headers.Add("POLY_TIMESTAMP", tsSec)
            req.Headers.Add("POLY_ADDRESS", _signerAddress.ToLowerInvariant())  ' CRITICAL: Lowercase for consistency
            req.Headers.Add("POLY_SIGNATURE", sig)
            
            ' CORRECTED: Only L2 authentication required for /order endpoint
            ' L1 authentication is handled by the EIP-712 signature within the order object itself
            Console.WriteLine($"[DEBUG] FINAL Headers (L2 Authentication Only):")
            Console.WriteLine($"[DEBUG]   POLY_API_KEY: {_apiKey}")
            Console.WriteLine($"[DEBUG]   POLY_PASSPHRASE: {_apiPassphrase}")
            Console.WriteLine($"[DEBUG]   POLY_TIMESTAMP: {tsSec}")
            Console.WriteLine($"[DEBUG]   POLY_ADDRESS: {_signerAddress.ToLowerInvariant()}")
            Console.WriteLine($"[DEBUG]   POLY_SIGNATURE: {sig}")
            Console.WriteLine($"[DEBUG] Authentication: L2 (API Key HMAC) Only - L1 is in order EIP-712 signature")

            Try
                Dim resp = Await client.SendAsync(req).ConfigureAwait(False)
                Dim txt = Await resp.Content.ReadAsStringAsync().ConfigureAwait(False)
                
                ' Log response for debugging
                Console.WriteLine($"[DEBUG] Response status: {CInt(resp.StatusCode)} {resp.ReasonPhrase}")
                Console.WriteLine($"[DEBUG] Response headers:")
                For Each header In resp.Headers
                    Console.WriteLine($"[DEBUG]   {header.Key}: {String.Join(", ", header.Value)}")
                Next
                Console.WriteLine($"[DEBUG] Response body: {txt}")
                Console.WriteLine()
                
                If resp.IsSuccessStatusCode Then
                    Console.WriteLine($"[OK] Order placed: {txt}")
                ElseIf CInt(resp.StatusCode) = 401 Then
                    Console.WriteLine($"[ERR] 401 Unauthorized - API key/signature issue: {txt}")
                ElseIf CInt(resp.StatusCode) = 400 Then
                    If txt.Contains("invalid api key") Then
                        Console.WriteLine($"[ERR] 400 Invalid API Key - Key mismatch between auth and order: {txt}")
                    ElseIf txt.Contains("invalid signature") Then
                        Console.WriteLine($"[ERR] 400 Invalid Signature - EIP-712 signing issue: {txt}")
                    ElseIf txt.Contains("invalid expiration") Then
                        Console.WriteLine($"[ERR] 400 Invalid Expiration - Time/expiration issue: {txt}")
                    Else
                        Console.WriteLine($"[ERR] 400 Bad Request: {txt}")
                    End If
                Else
                    Console.WriteLine($"[ERR] {CInt(resp.StatusCode)} - {txt}")
                End If
                
                Return (CInt(resp.StatusCode), txt)
                
            Catch ex As Exception
                Console.WriteLine($"[ERR] Exception during order placement: {ex.Message}")
                Return (0, $"Exception: {ex.Message}")
            End Try
        End Using
    End Function

    ' ================= helpers =================
    Private Shared Function NormalizeHexAddress(addr As String) As String
        Dim a = If(addr, String.Empty).Trim()
        If a.StartsWith("0X") Then a = "0x" & a.Substring(2)
        If Not System.Text.RegularExpressions.Regex.IsMatch(a, "^0x[0-9a-fA-F]{40}$") Then
            Throw New ArgumentException("Address must be a 0x-prefixed 40-hex-character string.")
        End If
        Return a.ToLowerInvariant()
    End Function

    Private Shared Function NormalizePrivKey(pk As String) As String
        Dim k = If(pk, String.Empty).Trim()
        If k.StartsWith("0x", StringComparison.OrdinalIgnoreCase) Then k = k.Substring(2)
        If Not System.Text.RegularExpressions.Regex.IsMatch(k, "^[0-9a-fA-F]{64}$") Then
            Throw New ArgumentException("Private key must be a 64-hex-character string (optionally prefixed with 0x).")
        End If
        Return k
    End Function

    Private Shared Function Base64UrlDecodeStrict(s As String) As Byte()
        Dim t = (If(s, "").Trim().Replace("-", "+").Replace("_", "/"))
        Select Case t.Length Mod 4
            Case 2 : t &= "=="
            Case 3 : t &= "="
        End Select
        Return Convert.FromBase64String(t)
    End Function

    Private Shared Function Base64UrlEncode(data As Byte()) As String
        Dim b64 As String = Convert.ToBase64String(data)
        ' Make URL-safe: replace +/ with -_ and KEEP padding to match official client
        Dim t As String = b64.Replace("+", "-").Replace("/", "_")
        Return t
    End Function

    Private Shared Function RandomUint256BigInteger() As System.Numerics.BigInteger
        Dim bytes(31) As Byte
        Using rng As New RNGCryptoServiceProvider()
            rng.GetBytes(bytes)
        End Using
        bytes(0) = CByte(bytes(0) And &H7F) ' positive
        ' BigInteger expects little-endian; reverse so that random big-endian bytes parse correctly
        Return New System.Numerics.BigInteger(bytes.Reverse().ToArray())
    End Function

    ' ================= GAMMA API: Fetch Market Data =================
    Public Shared Async Function GetMarketBySlugAsync(slug As String) As Task(Of JObject)
        ' Try the correct endpoint format: /markets?slug=
        Dim gammaUrl As String = $"https://gamma-api.polymarket.com/markets?slug={slug}"
        
        Using client As New HttpClient()
            Dim resp = Await client.GetAsync(gammaUrl).ConfigureAwait(False)
            Dim txt = Await resp.Content.ReadAsStringAsync().ConfigureAwait(False)
            
            If resp.IsSuccessStatusCode Then
                ' The API returns an array, get the first market
                Dim markets = JArray.Parse(txt)
                If markets.Count > 0 Then
                    Return CType(markets(0), JObject)
                Else
                    Throw New Exception($"No market found with slug: {slug}")
                End If
            Else
                Throw New Exception($"Gamma API error: {CInt(resp.StatusCode)} - {txt}")
            End If
        End Using
    End Function

    ''' <summary>
    ''' Sign a message with private key for L1 authentication
    ''' </summary>
    Private Function SignWithPrivateKey(message As String, privateKey As String) As String
        Try
            ' For now, use the same EIP-712 signer we already have
            ' This is a simplified approach - the proper L1 signature would be different
            Dim signer = New Eip712TypedDataSigner()
            
            ' Create a simple message signature (this may need adjustment based on Polymarket's exact requirements)
            ' Framework 4.8 compatible hex conversion
            Dim messageBytes As Byte() = Encoding.UTF8.GetBytes(message)
            Dim messageHash As String = BitConverter.ToString(messageBytes).Replace("-", "").ToLowerInvariant()
            Return "0x" & messageHash.Substring(0, Math.Min(128, messageHash.Length)).PadRight(128, "0"c)
            
        Catch ex As Exception
            Console.WriteLine($"[ERR] L1 signing failed: {ex.Message}")
            Return "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        End Try
    End Function
End Class

' ================= Minimal smoke/test routines =================
Module PolySmoke

    ' Run this to confirm L2 auth is stable repeatedly without restart.
    ' NOTE: Delay is ONLY in the test harness—orders remain single-shot.
    Public Sub RunL2CycleTest(baseUrl As String, apiKey As String, apiSecret As String, passphrase As String, eoa As String, privKey As String, Optional funder As String = Nothing, Optional sigType As Integer = 0)
        Dim api = New PolyTradingApi(baseUrl, apiKey, apiSecret, passphrase, eoa, privKey, funder, sigType)

        ' Prime the time offset once
        Dim syncMethod = GetType(PolyTradingApi).GetMethod("SyncServerTimeAsync", Reflection.BindingFlags.NonPublic Or Reflection.BindingFlags.Instance)
        Dim syncTask = CType(syncMethod.Invoke(api, Nothing), Threading.Tasks.Task)
        syncTask.GetAwaiter().GetResult()

        For i As Integer = 1 To 6
            Dim res = api.TestL2AuthAsync(forceResyncFirst:=(i = 1)).Result
            Console.WriteLine($"[{i}] L2 status={res.status} body={res.body}")
            If i < 6 Then Thread.Sleep(1300) ' ~1.3s so each test lands in a fresh second
        Next
    End Sub

    ' Full flow if you want it later (derive -> L2 -> optional order)
    Public Sub RunDeriveThenAuthAndMaybeOrder(eoa As String, privKey As String, tokenId As String)
        ' 1) Derive credentials (uses server seconds)
        Dim creds = PolyTradingApi.DeriveApiCredentials(eoa, privKey)
        Console.WriteLine($"DERIVED apiKey={creds.apiKey}")

        ' 2) Create client and sanity-check L2 (server-seconds + HMAC)
        Dim api = New PolyTradingApi("https://clob.polymarket.com",
                                     creds.apiKey,
                                     creds.secret,
                                     creds.passphrase,
                                     eoa,
                                     privKey)

        ' prime offset
        Dim syncMethod = GetType(PolyTradingApi).GetMethod("SyncServerTimeAsync", Reflection.BindingFlags.NonPublic Or Reflection.BindingFlags.Instance)
        Dim syncTask = CType(syncMethod.Invoke(api, Nothing), Threading.Tasks.Task)
        syncTask.GetAwaiter().GetResult()

        Dim l2 = api.TestL2AuthAsync().Result
        Console.WriteLine($"L2 {l2.status}: {l2.body}")

        ' 3) (Optional) Place a tiny FOK buy to test (payload already fixed)
        If l2.status = 200 AndAlso Not String.IsNullOrWhiteSpace(tokenId) Then
            Dim exp As Long = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120
            Dim order = api.BuildSignedOrder(tokenId, price:=0.05D, sizeShares:=1D, side:=0, expirationUnix:=exp)
            Dim placed = api.PlaceOrderAsync(order, "FOK", "vb_test_001").Result
            Console.WriteLine($"POST /order {placed.status}: {placed.body}")
        End If
    End Sub

    Public Sub RunOrderSmoke(
    baseUrl As String,
    apiKey As String,
    apiSecret As String,
    passphrase As String,
    signerEOA As String,
    signerPrivHex As String,
    tokenId As String,
    price As Decimal,
    sizeShares As Decimal,
    side As Integer,                       ' 0=BUY, 1=SELL
    Optional funder As String = Nothing,   ' proxy/funder address for non-EOA
    Optional sigType As Integer = 0,       ' 0=EOA, 1=Proxy, 2=Gnosis
    Optional orderType As String = "FOK",
    Optional feeBps As String = "0"
)
        Dim api = New PolyTradingApi(baseUrl, apiKey, apiSecret, passphrase, signerEOA, signerPrivHex, funder, sigType)

        ' Prime time offset once so PlaceOrderAsync uses server-aligned seconds (bounded).
        Dim syncMethod = GetType(PolyTradingApi).GetMethod("SyncServerTimeAsync", Reflection.BindingFlags.NonPublic Or Reflection.BindingFlags.Instance)
        Dim syncTask = CType(syncMethod.Invoke(api, Nothing), Threading.Tasks.Task)
        syncTask.GetAwaiter().GetResult()

        ' Polymarket enforces a minimum TTL (use >= +60s; +120s is safer)
        Dim exp As Long = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120

        ' Build signed order (note: side is stringified inside; salt is numeric)
        Dim order = api.BuildSignedOrder(
            tokenId:=tokenId,
            price:=price,
            sizeShares:=sizeShares,
            side:=side,
            expirationUnix:=exp,
            feeBps:=feeBps
        )

        ' Send it (single-shot; no retries so it's time-sensitive safe)
        Dim placed = api.PlaceOrderAsync(order, orderType, "vb_order_smoke_001").Result
        Console.WriteLine($"POST /order {placed.status}: {placed.body}")
    End Sub
End Module
