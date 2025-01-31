#------------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation.
# All rights reserved.
#
# Adapted from the MSAL python library under MIT license
#
# This code is licensed under the MIT License.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions :
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#------------------------------------------------------------------------------

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET
import re
import uuid
from datetime import datetime, timedelta

def _xpath_of_root(route_to_leaf):
    # Construct an xpath suitable to find a root node which has a specified leaf
    return '/'.join(route_to_leaf + ['..'] * (len(route_to_leaf)-1))

class Mex(object):

    NS = {  # Also used by wstrust_*.py
        'wsdl': 'http://schemas.xmlsoap.org/wsdl/',
        'sp': 'http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702',
        'sp2005': 'http://schemas.xmlsoap.org/ws/2005/07/securitypolicy',
        'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
        'wsa': 'http://www.w3.org/2005/08/addressing',  # Duplicate?
        'wsa10': 'http://www.w3.org/2005/08/addressing',
        'http': 'http://schemas.microsoft.com/ws/06/2004/policy/http',
        'soap12': 'http://schemas.xmlsoap.org/wsdl/soap12/',
        'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy',
        's': 'http://www.w3.org/2003/05/soap-envelope',
        'wst': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
        'trust': "http://docs.oasis-open.org/ws-sx/ws-trust/200512",  # Duplicate?
        'saml': "urn:oasis:names:tc:SAML:1.0:assertion",
        'wst2005': 'http://schemas.xmlsoap.org/ws/2005/02/trust',  # was named "t"
        }
    ACTION_13 = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue'
    ACTION_2005 = 'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue'

    def __init__(self, mex_document):
        self.dom = ET.fromstring(mex_document)

    def _get_policy_ids(self, components_to_leaf, binding_xpath):
        id_attr = '{%s}Id' % self.NS['wsu']
        return set(["#{}".format(policy.get(id_attr))
            for policy in self.dom.findall(_xpath_of_root(components_to_leaf), self.NS)
            # If we did not find any binding, this is potentially bad.
            if policy.find(binding_xpath, self.NS) is not None])

    def _get_username_password_policy_ids(self):
        path = ['wsp:Policy', 'wsp:ExactlyOne', 'wsp:All',
            'sp:SignedEncryptedSupportingTokens', 'wsp:Policy',
            'sp:UsernameToken', 'wsp:Policy', 'sp:WssUsernameToken10']
        policies = self._get_policy_ids(path, './/sp:TransportBinding')
        path2005 = ['wsp:Policy', 'wsp:ExactlyOne', 'wsp:All',
            'sp2005:SignedSupportingTokens', 'wsp:Policy',
            'sp2005:UsernameToken', 'wsp:Policy', 'sp2005:WssUsernameToken10']
        policies.update(self._get_policy_ids(path2005, './/sp2005:TransportBinding'))
        return policies

    def _get_iwa_policy_ids(self):
        return self._get_policy_ids(
            ['wsp:Policy', 'wsp:ExactlyOne', 'wsp:All', 'http:NegotiateAuthentication'],
            './/sp2005:TransportBinding')

    def _get_bindings(self):
        bindings = {}  # {binding_name: {"policy_uri": "...", "version": "..."}}
        for binding in self.dom.findall("wsdl:binding", self.NS):
            if (binding.find('soap12:binding', self.NS).get("transport") !=
                    'http://schemas.xmlsoap.org/soap/http'):
                continue
            action = binding.find(
                'wsdl:operation/soap12:operation', self.NS).get("soapAction")
            for pr in binding.findall("wsp:PolicyReference", self.NS):
                bindings[binding.get("name")] = {
                    "policy_uri": pr.get("URI"), "action": action}
        return bindings

    def _get_endpoints(self, bindings, policy_ids):
        endpoints = []
        for port in self.dom.findall('wsdl:service/wsdl:port', self.NS):
            binding_name = port.get("binding").split(':')[-1]  # Should have 2 parts
            binding = bindings.get(binding_name)
            if binding and binding["policy_uri"] in policy_ids:
                address = port.find('wsa10:EndpointReference/wsa10:Address', self.NS)
                if address is not None and address.text.lower().startswith("https://"):
                    endpoints.append(
                        {"address": address.text, "action": binding["action"]})
        return endpoints

    def get_wstrust_username_password_endpoint(self):
        """Returns {"address": "https://...", "action": "the soapAction value"}"""
        endpoints = self._get_endpoints(
                self._get_bindings(), self._get_username_password_policy_ids())
        for e in endpoints:
            if e["action"] == self.ACTION_13:
                return e  # Historically, we prefer ACTION_13 a.k.a. WsTrust13
        return endpoints[0] if endpoints else None


def send_auth_request(
        username, password, cloud_audience_urn, endpoint_address, soap_action, http_client,
        **kwargs):
    if not endpoint_address:
        raise ValueError("WsTrust endpoint address can not be empty")
    if soap_action is None:
        if '/trust/2005/usernamemixed' in endpoint_address:
            soap_action = Mex.ACTION_2005
        elif '/trust/13/usernamemixed' in endpoint_address:
            soap_action = Mex.ACTION_13
    if soap_action not in (Mex.ACTION_13, Mex.ACTION_2005):
        raise ValueError("Unsupported soap action: %s. "
            "Contact your administrator to check your ADFS's MEX settings." % soap_action)
    data = build_rst(
        username, password, cloud_audience_urn, endpoint_address, soap_action)
    resp = http_client.post(endpoint_address, data=data, headers={
            'Content-type':'application/soap+xml; charset=utf-8',
            'SOAPAction': soap_action,
            }, **kwargs)
    if resp.status_code >= 400:
        print("Unsuccessful WsTrust request receives: %s", resp.text)
    # It turns out ADFS uses 5xx status code even with client-side incorrect password error
    # resp.raise_for_status()
    return parse_wstrust_response(resp.text)


def escape_password(password):
    return (password.replace('&', '&amp;').replace('"', '&quot;')
        .replace("'", '&apos;')  # the only one not provided by cgi.escape(s, True)
        .replace('<', '&lt;').replace('>', '&gt;'))


def wsu_time_format(datetime_obj):
    # WsTrust (http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html)
    # does not seem to define timestamp format, but we see YYYY-mm-ddTHH:MM:SSZ
    # here (https://www.ibm.com/developerworks/websphere/library/techarticles/1003_chades/1003_chades.html)
    # It avoids the uncertainty of the optional ".ssssss" in datetime.isoformat()
    # https://docs.python.org/2/library/datetime.html#datetime.datetime.isoformat
    return datetime_obj.strftime('%Y-%m-%dT%H:%M:%SZ')


def build_rst(username, password, cloud_audience_urn, endpoint_address, soap_action):
    now = datetime.utcnow()
    return """<s:Envelope xmlns:s='{s}' xmlns:wsa='{wsa}' xmlns:wsu='{wsu}'>
        <s:Header>
            <wsa:Action s:mustUnderstand='1'>{soap_action}</wsa:Action>
            <wsa:MessageID>urn:uuid:{message_id}</wsa:MessageID>
            <wsa:ReplyTo>
            <wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address>
            </wsa:ReplyTo>
            <wsa:To s:mustUnderstand='1'>{endpoint_address}</wsa:To>

            <wsse:Security s:mustUnderstand='1'
            xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>
                <wsu:Timestamp wsu:Id='_0'>
                    <wsu:Created>{time_now}</wsu:Created>
                    <wsu:Expires>{time_expire}</wsu:Expires>
                </wsu:Timestamp>
                <wsse:UsernameToken wsu:Id='ADALUsernameToken'>
                    <wsse:Username>{username}</wsse:Username>
                    <wsse:Password>{password}</wsse:Password>
                </wsse:UsernameToken>
            </wsse:Security>

        </s:Header>
        <s:Body>
        <wst:RequestSecurityToken xmlns:wst='{wst}'>
        <wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>
            <wsa:EndpointReference>
                <wsa:Address>{applies_to}</wsa:Address>
            </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wst:KeyType>{key_type}</wst:KeyType>
            <wst:RequestType>{request_type}</wst:RequestType>
        </wst:RequestSecurityToken>
        </s:Body>
        </s:Envelope>""".format(
            s=Mex.NS["s"], wsu=Mex.NS["wsu"], wsa=Mex.NS["wsa10"],
            soap_action=soap_action, message_id=str(uuid.uuid4()),
            endpoint_address=endpoint_address,
            time_now=wsu_time_format(now),
            time_expire=wsu_time_format(now + timedelta(minutes=10)),
            username=username, password=escape_password(password),
            wst=Mex.NS["wst"] if soap_action == Mex.ACTION_13 else Mex.NS["wst2005"],
            applies_to=cloud_audience_urn,
            key_type='http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer'
                if soap_action == Mex.ACTION_13 else
                'http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey',
            request_type='http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'
                if soap_action == Mex.ACTION_13 else
                'http://schemas.xmlsoap.org/ws/2005/02/trust/Issue',
        )

def parse_wstrust_response(body):  # Returns {"token": "<saml:assertion ...>", "type": "..."}
    token = parse_token_by_re(body)
    if token:
        return token
    error = parse_wstrust_error(body)
    return error

def parse_wstrust_error(body):  # Returns error as a dict. See unit test case for an example.
    dom = ET.fromstring(body)
    reason_text_node = dom.find('s:Body/s:Fault/s:Reason/s:Text', Mex.NS)
    subcode_value_node = dom.find('s:Body/s:Fault/s:Code/s:Subcode/s:Value', Mex.NS)
    if reason_text_node is not None or subcode_value_node is not None:
        return {"reason": reason_text_node.text, "code": subcode_value_node.text}

def findall_content(xml_string, tag):
    """
    Given a tag name without any prefix,
    this function returns a list of the raw content inside this tag as-is.

    >>> findall_content("<ns0:foo> what <bar> ever </bar> content </ns0:foo>", "foo")
    [" what <bar> ever </bar> content "]

    Motivation:

    Usually we would use XML parser to extract the data by xpath.
    However the ElementTree in Python will implicitly normalize the output
    by "hoisting" the inner inline namespaces into the outmost element.
    The result will be a semantically equivalent XML snippet,
    but not fully identical to the original one.
    While this effect shouldn't become a problem in all other cases,
    it does not seem to fully comply with Exclusive XML Canonicalization spec
    (https://www.w3.org/TR/xml-exc-c14n/), and void the SAML token signature.
    SAML signature algo needs the "XML -> C14N(XML) -> Signed(C14N(Xml))" order.

    The binary extention lxml is probably the canonical way to solve this
    (https://stackoverflow.com/questions/22959577/python-exclusive-xml-canonicalization-xml-exc-c14n)
    but here we use this workaround, based on Regex, to return raw content as-is.
    """
    # \w+ is good enough for https://www.w3.org/TR/REC-xml/#NT-NameChar
    pattern = r"<(?:\w+:)?%(tag)s(?:[^>]*)>(.*)</(?:\w+:)?%(tag)s" % {"tag": tag}
    return re.findall(pattern, xml_string, re.DOTALL)

def parse_token_by_re(raw_response):  # Returns the saml:assertion
    for rstr in findall_content(raw_response, "RequestSecurityTokenResponse"):
        token_types = findall_content(rstr, "TokenType")
        tokens = findall_content(rstr, "RequestedSecurityToken")
        if token_types and tokens:
            # Historically, we use "us-ascii" encoding, but it should be "utf-8"
            # https://stackoverflow.com/questions/36658000/what-is-encoding-used-for-saml-conversations
            return {"token": tokens[0], "type": token_types[0]}

