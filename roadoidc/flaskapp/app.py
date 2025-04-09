from flask import Flask, render_template, session, request, redirect, url_for, abort, jsonify
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography import x509
import base64
import requests
import app_config

app = Flask(__name__)
app.config.from_object(app_config)

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

@app.route("/.well-known/openid-configuration")
def oidc():
    data = {
      "token_endpoint": f"{app_config.ISSUER}/token",
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "private_key_jwt",
        "client_secret_basic"
      ],
      "jwks_uri": f"{app_config.ISSUER}/keys.json",
      "response_modes_supported": [
        "query",
        "fragment",
        "form_post"
      ],
      "subject_types_supported": [
        "pairwise"
      ],
      "id_token_signing_alg_values_supported": [
        "RS256"
      ],
      "response_types_supported": [
        "code",
        "id_token",
        "code id_token",
        "id_token token"
      ],
      "scopes_supported": [
        "openid",
        "profile",
        "email",
        "offline_access"
      ],
      "issuer": app_config.ISSUER,
      "request_uri_parameter_supported": False,
      "userinfo_endpoint": f"{app_config.ISSUER}/oidc/userinfo",
      "authorization_endpoint": f"{app_config.ISSUER}/authorize",
      "http_logout_supported": True,
      "frontchannel_logout_supported": True,
      "claims_supported": [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "acr",
        "nonce",
        "name",
        "tid",
        "ver",
        "at_hash",
        "c_hash",
        "email"
      ]
    }
    return jsonify(data)

@app.route("/keys.json")
def servekeys():
    key = serialization.load_pem_private_key(app_config.PRIVKEY.encode('utf-8'), password=None)
    pubnumbers = key.public_key().public_numbers()

    cert = x509.load_pem_x509_certificate(app_config.CERT.encode('utf-8'))
    certder = cert.public_bytes(serialization.Encoding.DER)
    certbytes = base64.b64encode(certder)

    # From python docs https://docs.python.org/3/library/stdtypes.html#int.to_bytes
    exponent_as_bytes = pubnumbers.e.to_bytes((pubnumbers.e.bit_length() + 7) // 8, byteorder='big')
    modulus_as_bytes = pubnumbers.n.to_bytes((pubnumbers.n.bit_length() + 7) // 8, byteorder='big')
    jwks = {
        'keys': [{
            'kty': 'RSA',
            'use': 'sig',
            'e': base64.b64encode(exponent_as_bytes).decode('utf-8'),
            'n': base64.b64encode(modulus_as_bytes).decode('utf-8'),
            'alg': 'RS256',
            'kid': app_config.KEYID,
            'x5c': [certbytes.decode('utf-8')]
        }]
    }
    return jsonify(jwks)

if __name__ == "__main__":
    app.run()
