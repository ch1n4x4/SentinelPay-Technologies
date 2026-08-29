# SentinelPay API Reference

Base URLs (local):
- payments-api: `http://localhost:8001`
- kyc-api:      `http://localhost:8002`

All endpoints except `/health`, `/v1/auth/register`, and `/v1/auth/login`
require a `Bearer` token in the `Authorization` header.

## payments-api

### Auth
| Method | Path                  | Description                            |
| ------ | --------------------- | -------------------------------------- |
| POST   | `/v1/auth/register`   | Create a new user                      |
| POST   | `/v1/auth/login`      | Authenticate and receive a JWT         |
| POST   | `/v1/auth/otp`        | Request an OTP for step-up auth        |

### Accounts
| Method | Path                              | Description                       |
| ------ | --------------------------------- | --------------------------------- |
| GET    | `/v1/accounts/`                   | List the caller's accounts        |
| GET    | `/v1/accounts/{id}`               | Fetch an account by ID            |
| PUT    | `/v1/accounts/{id}/profile`       | Update profile fields             |

### Transactions
| Method | Path                              | Description                       |
| ------ | --------------------------------- | --------------------------------- |
| GET    | `/v1/transactions/search?q=...`   | Search transactions               |
| GET    | `/v1/transactions/{reference}`    | Get a transaction by reference    |

### Wallets
| Method | Path                                | Description                     |
| ------ | ----------------------------------- | ------------------------------- |
| POST   | `/v1/wallets/{account_id}/credit`   | Credit a wallet                 |
| POST   | `/v1/wallets/{account_id}/debit`    | Debit a wallet                  |

### Webhooks
| Method | Path                  | Description                         |
| ------ | --------------------- | ----------------------------------- |
| POST   | `/v1/webhooks/`       | Register a webhook callback URL     |
| POST   | `/v1/webhooks/test`   | Test-fire a webhook URL             |

### Admin
| Method | Path                          | Description                       |
| ------ | ----------------------------- | --------------------------------- |
| GET    | `/v1/admin/users`             | List all users (admin only)       |
| POST   | `/v1/admin/session/restore`   | Restore an admin session blob     |

## kyc-api

### Verify
| Method | Path                  | Description                            |
| ------ | --------------------- | -------------------------------------- |
| POST   | `/v1/verify/bvn`      | Verify a BVN against an upstream       |
| GET    | `/v1/verify/lookup`   | Look up KYC records by BVN or NIN      |

### Documents
| Method | Path                          | Description                       |
| ------ | ----------------------------- | --------------------------------- |
| POST   | `/v1/documents/upload`        | Upload a KYC document             |
| GET    | `/v1/documents/{key}`         | Fetch a previously uploaded doc   |

## Example: full happy path

```bash
# Register
curl -X POST http://localhost:8001/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"password123","full_name":"Test User"}'

# Login
TOKEN=$(curl -s -X POST http://localhost:8001/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"password123"}' | jq -r .token)

# List accounts (will be empty for a new user)
curl http://localhost:8001/v1/accounts/ -H "Authorization: Bearer $TOKEN"

# Credit a wallet (account 3 is seeded)
curl -X POST http://localhost:8001/v1/wallets/3/credit \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"amount":"1000.00","description":"test credit"}'
```
