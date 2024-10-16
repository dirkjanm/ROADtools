from flask import Flask, render_template, render_template_string, session, request, redirect, url_for, abort, jsonify
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography import x509
import base64
import requests
import time
import app_config
import jwt

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

@app.route("/eam/authorize", methods=['POST','GET'])
def eam_authorize():
    tpl = '''
    <html><head><title>Working...</title></head><body>
<form method="POST" name="hiddenform" action="{{ redirurl }}">
<input type="hidden" name="token_type" value="Bearer" />
<input type="hidden" name="id_token" value="{{ id_token }}" />
<input type="hidden" name="expires_in" value="300" />
<input type="hidden" name="state" value="{{ state }}" />
<input type="hidden" name="scope" value="openid" /><noscript><p>Script is disabled. Click Submit to continue.</p>
<input type="submit" value="Submit" /></noscript></form><script language="javascript">function submit_form(){window.setTimeout('document.forms[0].submit()', 0);}window.onload=submit_form;</script></body></html>
    '''
    encoded = request.form['id_token_hint']
    id_token_hint = jwt.decode(encoded, options={"verify_signature": False})


    payload = {
      "iss": f"{app_config.ISSUER}/eam",
      "sub": id_token_hint['sub'],
      "aud": request.form['client_id'],
      "exp": int(time.time())+300,
      "iat": int(time.time()),
      "nonce": request.form['nonce'],
      "DuoMfa": "MfaDone",
      "acr": "possessionorinherence",
      "amr": [
        "fido"
      ]
    }
    headers = {
        "kid": "ROIDKEY",
    }
    token = jwt.encode(payload, algorithm='RS256', key=app_config.PRIVKEY.encode('utf-8'), headers=headers)
    return render_template_string(tpl, redirurl=request.form['redirect_uri'], state=request.form['state'], id_token=token)

@app.route("/eam/.well-known/openid-configuration")
def eamoidc():
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
      "issuer": f"{app_config.ISSUER}/eam",
      "request_uri_parameter_supported": False,
      "userinfo_endpoint": f"{app_config.ISSUER}/oidc/userinfo",
      "authorization_endpoint": f"{app_config.ISSUER}/eam/authorize",
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

if __name__ == "__main__":
    app.run()
