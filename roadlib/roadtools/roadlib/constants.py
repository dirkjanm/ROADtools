"""
Constants for roadlib containing well-known resources, login templates (xml), etc
"""

WELLKNOWN_RESOURCES = {
    "msgraph": "https://graph.microsoft.com/",
    "aadgraph": "https://graph.windows.net/",
    "devicereg": "urn:ms-drs:enterpriseregistration.windows.net",
    "drs": "urn:ms-drs:enterpriseregistration.windows.net",
    "azrm": "https://management.core.windows.net/",
    "azurerm": "https://management.core.windows.net/",
    "outlook": "https://outlook.office.com/",
    "sharepoint": "00000003-0000-0ff1-ce00-000000000000"
}

WELLKNOWN_CLIENTS = {
    "aadps": "1b730954-1685-4b74-9bfd-dac224a7b894",
    "azcli": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "msteams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "azps": "1950a258-227b-4e31-a9cf-717495945fc2",
    "msedge": "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "edge": "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "msbroker": "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "broker": "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "companyportal": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
}

WELLKNOWN_USER_AGENTS = {
    "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "edge_windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "edge_android": "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.66 Mobile Safari/537.36 EdgA/118.0.2088.66",
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "chrome_windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "chrome_android": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.3",
    "chrome_macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "chrome_linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.3",
    "chrome_ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.6045.109 Mobile/15E148 Safari/604.",
    "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "firefox_windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "firefox_macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
    "firefox_ubuntu": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.1",
    "safari_macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.1",
    "safari_ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.",
    "empty": "No user agent header"
}

DSSO_BODY_KERBEROS = '''<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope
    xmlns:s='http://www.w3.org/2003/05/soap-envelope'
    xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion'
    xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'
    xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
    xmlns:wsa='http://www.w3.org/2005/08/addressing'
    xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc'
    xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>https://autologon.microsoftazuread-sso.com/{tenant}/winauth/trust/2005/windowstransport?client-request-id=4190b9ab-205d-4024-8caa-aedb3f79988b</wsa:To>
        <wsa:MessageID>urn:uuid:36a2e970-3107-4e3f-99dd-569a9588f02c</wsa:MessageID>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
            <wsp:AppliesTo>
                <wsa:EndpointReference>
                    <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                </wsa:EndpointReference>
            </wsp:AppliesTo>
            <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>
'''

DSSO_BODY_USERPASS = '''<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>
  <s:Header>
    <a:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:MessageID>urn:uuid:a5c80716-16fe-473c-bb5d-be0602f9e7fd</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand='1'>https://autologon.microsoftazuread-sso.com/{tenant}/winauth/trust/2005/usernamemixed?client-request-id=19ac39db-81d2-4713-8046-b0b7240592be</a:To>
    <o:Security s:mustUnderstand='1' xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>
      <u:Timestamp u:Id='_0'>
        <u:Created>2020-11-23T14:50:44.068Z</u:Created>
        <u:Expires>2020-11-23T15:00:44.068Z</u:Expires>
      </u:Timestamp>
      <o:UsernameToken u:Id='uuid-3e66cabc-66d3-4447-a1c2-ef7ba45274f7'>
        <o:Username>{username}</o:Username>
        <o:Password>{password}</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <trust:RequestSecurityToken xmlns:trust='http://schemas.xmlsoap.org/ws/2005/02/trust'>
      <wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>
        <a:EndpointReference>
          <a:Address>urn:federation:MicrosoftOnline</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
      <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
    </trust:RequestSecurityToken>
  </s:Body>
</s:Envelope>
'''

SAML_TOKEN_TYPE_V1 = 'urn:oasis:names:tc:SAML:1.0:assertion'
SAML_TOKEN_TYPE_V2 = 'urn:oasis:names:tc:SAML:2.0:assertion'
GRANT_TYPE_SAML1_1 = 'urn:ietf:params:oauth:grant-type:saml1_1-bearer'
GRANT_TYPE_SAML2 = "urn:ietf:params:oauth:grant-type:saml2-bearer"

# http://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SAMLTokenProfile-v1.1.1-os.html#_Toc307397288
WSS_SAML_TOKEN_PROFILE_V1_1 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
WSS_SAML_TOKEN_PROFILE_V2 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
