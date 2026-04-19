# timestamping-poc-golang

A proof-of-concept **RFC 3161 Time Stamp Authority (TSA)** server written in Go.

On startup the server generates an ephemeral two-level PKI (Root CA → TSA leaf) and begins accepting timestamp requests.
The keys are in-memory only; they are regenerated on every restart.

## Features

- RFC 3161 compliant timestamp token generation
- Ephemeral RSA-2048 PKI (Root CA + TSA leaf) generated at startup
- Nonce replay-detection with a configurable TTL window (default: 5 minutes)
- TSA policy OID validation — configurable allow-list
- Simulated time-quality monitor (NTP check); rejects requests when time quality is `FAILED`
- Snowflake-based unique serial numbers for issued tokens

## Requirements

- Go 1.22+

## Running

```bash
go run .
```

The server listens on port `8080` by default. Override with the `PORT` environment variable:

```bash
PORT=9000 go run .
```

## API

### Sign a timestamp request

```
POST /api/v1/protocols/tsp/{profileName}/sign
Content-Type: application/timestamp-query

<DER-encoded TimeStampReq>
```

**Response**

```
Content-Type: application/timestamp-reply

<DER-encoded TimeStampResp>
```

### Example with OpenSSL

```bash
# Create a hash of the file to timestamp
openssl ts -query -data myfile.txt -no_nonce -sha256 -out request.tsq

# Send to the TSA
curl -s -S -X POST \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @request.tsq \
  http://localhost:8080/api/v1/protocols/tsp/default/sign \
  -o response.tsr

# Verify (requires the CA cert — not applicable here since certs are ephemeral)
openssl ts -reply -in response.tsr -text
```

## Configuration

`tsp.DefaultConfig()` provides production-oriented defaults:

| Setting            | Default                          | Description                              |
|--------------------|----------------------------------|------------------------------------------|
| `DefaultPolicyOID` | `1.3.6.1.4.1.99999.1`           | Policy embedded when client omits one    |
| `AllowedPolicyOIDs`| `[1.3.6.1.4.1.99999.1]`         | Set of accepted policy OIDs              |
| `NonceTTL`         | `5m`                             | Replay-detection window                  |

## Project structure

```
main.go                        – entry point; wires up crypto, service and HTTP server
internal/
  tsacrypto/chain.go           – generates the ephemeral Root CA + TSA leaf key pair
  tsp/
    app.go                     – Fiber app and route registration
    service.go                 – core signing logic
    handler.go                 – HTTP handler; parses requests and serialises responses
    config.go                  – Config struct and defaults
    policy.go                  – TSA policy OID allow-list validation
    nonce.go                   – in-memory nonce cache for replay prevention
    timequality.go             – simulated NTP time-quality monitor
    snowflake.go               – unique serial number generation
```

## Testing

```bash
go test ./...
```

## Notes

- This is a **proof of concept** — keys are ephemeral and not persisted. Do not use in production.
- The time-quality monitor simulates NTP failures randomly (1 % chance of `FAILED`, 4 % chance of `DEGRADED` on each 30-second tick).
