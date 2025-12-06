# UserAuthentication

## Data Storage Sizes

| Item           | SQL Server Type       | Size       | Bits   |
|----------------|-----------------------|------------|--------|
| Password Hash  | VARBINARY(32)         | 32 bytes   | 256    |
| Password Salt  | VARBINARY(16)         | 16 bytes   | 128    |
| Session Token  | VARBINARY(64)         | 64 bytes   | 512    |

## Notes

- **Password Hash:** Stored as a 32-byte PBKDF2 hash
- **Password Salt:** Stored as a 16-byte random salt, unique per user
- **Session Token:** Stored as a 64-byte random token (Base64-encoded when sent to clients)
