# core

Módulo base de zaws. Implementa AWS Signature V4 y resolución de credenciales.

## credentials.zig

| Función/Struct | Descripción |
|----------------|-------------|
| `Credentials` | Struct con access_key_id, secret_access_key, session_token |
| `resolve(environ)` | Lee credenciales desde variables de entorno |

## signing.zig

Implementación paso a paso de AWS Signature V4:

| # | Función | Descripción |
|---|---------|-------------|
| 1 | `hmac(key, message)` | HMAC-SHA256 — firma un message con una key, retorna 32 bytes |
| 2 | `sha256(data)` | Hash SHA256 — retorna 32 bytes |
| 3 | `deriveSigningKey(secret, date, region, service)` | Cadena de HMACs para derivar la signing key |
| 4 | `canonicalRequest(buf, info)` | Normaliza el HTTP request en formato AWS |
| 5 | `stringToSign(buf, amz_date, date, region, service, canonical)` | Construye el string que se firma |
| 6 | `sign(buf, info, date, region, service, secret, access_key)` | Firma final — retorna el header Authorization |

## Documentación AWS oficial

- [Guía completa Signature V4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- [Paso 1: Canonical Request](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html)
- [Paso 2: String to Sign](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html)
- [Paso 3: Signing Key](https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html)
- [Paso 4: Header Authorization](https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html)
- [Test suite (valores de referencia)](https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)

## Flujo completo

```
credentials.resolve()
        ↓
deriveSigningKey(secret, date, region, service)
        ↓
canonicalRequest(method, path, query, host, amz_date, body)
        ↓
stringToSign(amz_date, date, region, service, canonical)
        ↓
signature = hmac(signing_key, string_to_sign)
        ↓
Header Authorization listo
```
