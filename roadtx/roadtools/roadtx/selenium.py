import os
import sys
import requests
import codecs
import json
from urllib.parse import urlparse, parse_qs, quote_plus
from roadtools.roadlib.auth import Authentication, AuthenticationException, get_data, WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadtx.keepass import HackyKeePassFileReader
from seleniumwire.webdriver import FirefoxOptions
from seleniumwire import webdriver as webdriver_wire
from seleniumwire.thirdparty.mitmproxy.net.http import encoding
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common import exceptions
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException, \
    NoSuchElementException, ElementClickInterceptedException, ElementNotInteractableException
import pyotp

# Decorator for selenium functions
def selenium_wrap(func):
    def wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except exceptions.NoSuchWindowException as exc:
            if 'Browsing context has been discarded' in str(exc):
                print('Browser window was closed by the user')
                return False
            raise exc
        except exceptions.WebDriverException as exc:
            if 'Failed to decode response from marionette' in str(exc) or 'WebDriver session does not exist' in str(exc):
                print('Browser window closed by the user')
                return False
            raise exc
        except KeyboardInterrupt:
            print('Authentication was cancelled (KeyboardInterrupt raised)')
            return False
    return wrapped

class SeleniumAuthentication():
    def __init__(self, auth, deviceauth, redirurl, proxy=None, proxy_type="http"):
        if proxy:
            # Strip possible prefixes
            proxy = proxy.replace('http://','').replace('https://','').replace('socks://','').replace('socks4://','').replace('socks5://','')
        self.proxy = proxy
        self.proxy_type = proxy_type
        self.auth = auth
        self.deviceauth = deviceauth
        self.driver = None
        self.redirurl = redirurl
        self.headless = False

    def get_service(self, driverpath):
        # Default expects geckodriver to be in path, but if it exists locally we use that
        # newer selenium will auto manage this for us so driverpath is optional now
        if driverpath:
            if driverpath == 'geckodriver' and os.path.exists(driverpath):
                driverpath = './geckodriver'
            # Try to find the driver if a path is given
            if driverpath != 'geckodriver' and not os.path.exists(driverpath):
                print('geckodriver not found! Required for selenium operation. Please download from https://github.com/mozilla/geckodriver/releases')
                return False
        else:
            if os.path.exists('/snap/bin/geckodriver'):
                driverpath = '/snap/bin/geckodriver'
        service = Service(executable_path=driverpath)
        return service

    def get_webdriver(self, service, intercept=False):
        '''
        Load webdriver based on service, which is either
        from selenium or selenium-wire if interception is requested
        '''
        # Exclude some CDN hosts to massively speed up mitmproxy interception
        exclude_hosts = [
            'cdn.office.net',
            'res-1.cdn.office.net',
            'aadcdn.msauth.net',
            'cdn.mozilla.net',
            'amcdn.msftauth.net',
            'afd-v2.hosting.portal.azure.net',
            'reactblade.portal.azure.net'
        ]
        if self.proxy:
            options = {
                'proxy': {
                    'http': f'{self.proxy_type}://{self.proxy}',
                    'https': f'{self.proxy_type}://{self.proxy}',
                    'no_proxy': 'localhost,127.0.0.1'
                },
                'request_storage': 'memory',
                'exclude_hosts': exclude_hosts
            }
            # Force intercept to add proxy
            intercept = True
        else:
            options = {'request_storage': 'memory','exclude_hosts':exclude_hosts}
            if self.redir_has_custom_scheme():
                intercept = True
        if intercept and self.headless:
            firefox_options=FirefoxOptions()
            firefox_options.add_argument("-headless")
            driver = webdriver_wire.Firefox(service=service,  options=firefox_options, seleniumwire_options=options)
        elif intercept:
            driver = webdriver_wire.Firefox(service=service,  seleniumwire_options=options)
        else:
            driver = webdriver.Firefox(service=service)
        return driver

    @staticmethod
    def wait_till_text(driver, text):
        try:
            el = driver.find_element(By.ID, "message")
            if el:
                return text in str(el.text)
        except StaleElementReferenceException:
            return False
        return False

    def redir_has_custom_scheme(self):
        '''
        Check whether the redirect URL has a custom scheme
        In this case we try to replace this during the response since Firefox otherwise bugs out
        '''
        if not self.redirurl:
            return False
        parsed = urlparse(self.redirurl)
        return not parsed.scheme.lower() in ('http', 'https')

    def redir_interceptor(self, request, response):
        '''
        Intercept redirect response to replace custom scheme
        '''
        if request.url.startswith('https://login.microsoftonline.com/'):
            # Microsoft seems to auto-lowercase the redirect URL internally, but only the hostname
            if response.headers['Location'] and response.headers['Location'].lower().startswith(self.redirurl.lower()):
                parsed = urlparse(response.headers['Location'])
                newredir = "https://login.microsoftonline.com/common/oauth2/nativeclient"
                if parsed.query:
                    newredir += f'?{parsed.query}'
                if parsed.fragment:
                    newredir += f'#{parsed.fragment}'
                del response.headers['Location']
                response.headers['Location'] = newredir
            if request.url.startswith('https://login.microsoftonline.com/common/oauth2/nativeclient'):
                # Replace body with empty one to prevent redirect
                body = b'A nice blank page to give roadtx some time to capture the authorization code...'
                response.body = encoding.encode(body, response.headers.get('Content-Encoding', 'identity'))
                del response.headers['Content-Length']
                response.headers['Content-Length'] = len(response.body)
            if request.url.startswith('https://login.microsoftonline.com/appverify'):
                body = encoding.decode(response.body, response.headers.get('Content-Encoding', 'identity'))
                if b'document.location.replace' in body:
                    # url replace with javascript :(
                    startstring = b'document.location.replace("'
                    index = body.find(startstring) + len(startstring)
                    endstring = b'")'
                    endindex = body[index:].find(endstring) + index
                    urlstring = body[index:endindex].decode('utf-8')
                    if urlstring.lower().startswith(self.redirurl.lower()):
                        parsed = urlparse(urlstring)
                        newredir = "https://login.microsoftonline.com/common/oauth2/nativeclient"
                        if parsed.query:
                            newredir += f'?{parsed.query}'
                        if parsed.fragment:
                            newredir += f'#{parsed.fragment}'
                        body = body.replace(urlstring.encode('utf-8'), newredir.encode('utf-8'))
                        response.body = encoding.encode(body, response.headers.get('Content-Encoding', 'identity'))
                        del response.headers['Content-Length']
                        response.headers['Content-Length'] = len(response.body)

    def get_keepass_cred(self, identity, filepath, password):
        '''
        Get identity from KeePass file
        '''
        if not password and 'KPPASS' in os.environ:
            password = os.environ['KPPASS']

        if filepath.endswith('.xml'):
            reader = HackyKeePassFileReader(filepath, password, plain=True)
        else:
            if not password:
                raise AuthenticationException('No password was specified to decrypt the KeePass database')
            reader = HackyKeePassFileReader(filepath, password, plain=False)
        entry = reader.get_entry(identity)
        if not entry:
            raise AuthenticationException(f'Specified username {identity} not found in KeePass file')
        userpassword = entry['Password']
        try:
            otpseed = entry['otp']
        except KeyError:
            otpseed = None
        return userpassword, otpseed

    @selenium_wrap
    def selenium_login(self, url, identity=None, password=None, otpseed=None, keep=False, capture=False, federated=False, devicecode=None):
        '''
        Selenium based login with optional autofill of whatever is provided
        '''
        driver = self.driver
        # Change if using device code auth
        if devicecode:
            url = 'https://login.microsoftonline.com/common/oauth2/deviceauth'
        driver.get(url)
        # Enter code first if device code flow
        if devicecode:
            el = WebDriverWait(driver, 3000).until(lambda d: d.find_element(By.ID, "otc"))
            el.send_keys(devicecode + Keys.ENTER)
        if identity and not 'login_hint' in url:
            el = WebDriverWait(driver, 3000).until(lambda d: d.find_element(By.ID, "i0116"))
            el.send_keys(identity + Keys.ENTER)
        if password:
            if federated:
                els = WebDriverWait(driver, 6000).until(lambda d: d.find_element(By.ID, "passwordInput"))
                els.send_keys(password)
                try:
                    WebDriverWait(driver, 1).until(lambda d: d.find_element(By.ID, "idonotexist"))
                except TimeoutException:
                    pass
                els.send_keys(Keys.ENTER)
            else:
                els = WebDriverWait(driver, 6000).until(lambda d: d.find_element(By.ID, "i0118"))
                els.send_keys(password)

                el = WebDriverWait(driver, 6000).until(lambda d: d.find_element(By.ID, "idSIButton9"))
                try:
                    WebDriverWait(driver, 2).until(lambda d: d.find_element(By.ID, "idonotexist"))
                except TimeoutException:
                    pass
                els = WebDriverWait(driver, 6000).until(lambda d: d.find_element(By.ID, "i0118"))
                els.send_keys(Keys.ENTER)

        # Quick check of mfa not needed
        try:
            try:
                WebDriverWait(driver, 1).until(lambda d: d.find_element(By.ID, "idonotexist"))
            except TimeoutException:
                pass
            els = WebDriverWait(driver, 2).until(lambda d: '?code=' in d.current_url or d.find_element(By.ID, "idSIButton9"))
            if not '?code=' in driver.current_url:
                # handle KMSI first
                try:
                    WebDriverWait(driver, 1).until(lambda d: d.find_element(By.ID, "idonotexist"))
                except TimeoutException:
                    pass
                try:
                    driver.find_element(By.ID, "idSIButton9").click()
                except (ElementClickInterceptedException, ElementNotInteractableException, NoSuchElementException):
                    pass
                try:
                    WebDriverWait(driver, 2).until(lambda d: '?code=' in d.current_url)
                except NoSuchElementException:
                    raise TimeoutException
            res = urlparse(driver.current_url)
            params = parse_qs(res.query)
            code = params['code'][0]
            if not keep:
                driver.close()
            if capture:
                return code
            if self.auth.scope:
                return self.auth.authenticate_with_code_native_v2(code, self.redirurl)
            return self.auth.authenticate_with_code_native(code, self.redirurl)
        except TimeoutException:
            pass

        if otpseed:
            try:
                els = WebDriverWait(driver, 2).until(lambda d: d.find_element(By.CSS_SELECTOR, '[data-value="PhoneAppOTP"]'))
                els.click()
            except TimeoutException:
                pass
            otp = pyotp.TOTP(otpseed)
            now = str(otp.now())
            try:
                els = WebDriverWait(driver, 10).until(lambda d: d.find_element(By.ID, "idTxtBx_SAOTCC_OTC"))
                els.send_keys(now + Keys.ENTER)

            except TimeoutException:
                # No MFA?
                pass

        if devicecode:
            try:
                els = WebDriverWait(driver, 10).until(lambda d: d.find_element(By.ID, "idSIButton9"))
                els.click()
                try:
                    els = WebDriverWait(driver, 10).until(lambda d: self.wait_till_text(d, 'You have signed in'))
                except TimeoutException:
                    if not keep:
                        driver.close()
                        raise AuthenticationException('Could not verify whether device auth succeeded (success text not found)')
                if not keep:
                    driver.close()
                return True
            except TimeoutException:
                if not keep:
                    driver.close()
                    raise AuthenticationException('Could not complete device code auth within the time limit (button not found: idSIButton9)')
        else:
            try:
                els = WebDriverWait(driver, 1200).until(lambda d: '?code=' in d.current_url or d.find_element(By.ID, "idSIButton9"))
                if not '?code=' in driver.current_url:
                    # Handle KMSI
                    try:
                        driver.find_element(By.ID, "idSIButton9").click()
                    except (ElementClickInterceptedException, ElementNotInteractableException):
                        pass
                    WebDriverWait(driver, 1200).until(lambda d: '?code=' in d.current_url)
                res = urlparse(driver.current_url)
                params = parse_qs(res.query)
                code = params['code'][0]
                if not keep:
                    driver.close()
                if capture:
                    return code
                if self.auth.scope:
                    return self.auth.authenticate_with_code_native_v2(code, self.redirurl)
                return self.auth.authenticate_with_code_native(code, self.redirurl)
            except TimeoutException:
                if not keep:
                    driver.close()
                    raise AuthenticationException('Authentication did not complete within time limit')
        return False

    def selenium_login_with_custom_useragent(self, url, identity=None, password=None, otpseed=None, keep=False, capture=False, federated=False, devicecode=None):
        '''
        Wrapper for plain login with custom user agent (requires interception to change)
        '''
        def interceptor(request):
            del request.headers['User-Agent']
            request.headers['User-Agent'] = self.auth.user_agent
        self.driver.request_interceptor = interceptor
        self.driver.response_interceptor = self.redir_interceptor
        return self.selenium_login(url, identity=identity, password=password, otpseed=otpseed, keep=keep, capture=capture, federated=federated, devicecode=devicecode)

    def selenium_login_regular(self, url, identity=None, password=None, otpseed=None, keep=False, capture=False, federated=False, devicecode=None):
        '''
        Wrapper for plain login but with redirect URL rewrite support
        '''
        self.driver.response_interceptor = self.redir_interceptor
        return self.selenium_login(url, identity=identity, password=password, otpseed=otpseed, keep=keep, capture=capture, federated=federated, devicecode=devicecode)

    def selenium_login_with_prt(self, url, identity=None, password=None, otpseed=None, keep=False, prtcookie=None, capture=False):
        '''
        Selenium login with PRT injection.
        '''
        def interceptor(request):
            del request.headers['User-Agent']
            if self.auth.user_agent:
                request.headers['User-Agent'] = self.auth.user_agent
            else:
                request.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.71'
                request.headers['Sec-Ch-Ua'] = '" Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"'
                request.headers['Sec-Ch-Ua-Mobile'] =  '?0'
                request.headers['Sec-Ch-Ua-Platform'] =  '"Windows"'
                request.headers['Sec-Ch-Ua-Platform-Version'] = '"10.0.0"'

            if request.url.startswith('https://login.microsoftonline.com/'):
                if '/authorize' in request.url or '/login' in request.url or '/kmsi' in request.url or '/reprocess' in request.url or '/resume' in request.url:
                    if prtcookie:
                        # Force single cookie injection
                        if prtcookie == 'filerefresh':
                            try:
                                with codecs.open('.roadtools_prtcookie','r','utf-8') as infile:
                                    data = json.load(infile)
                                    cur_prtcookie = data['refreshTokenCredential']
                                request.headers['X-Ms-Refreshtokencredential'] = cur_prtcookie
                            except IOError:
                                print('Could not load PRT cookie from .roadtools_prtcookie file')
                            except KeyError:
                                print('No PRT cookie data found in .roadtools_prtcookie file')
                        else:
                            request.headers['X-Ms-Refreshtokencredential'] = prtcookie
                    else:
                        if 'sso_nonce' in request.url:
                            res = urlparse(request.url)
                            params = parse_qs(res.query)
                            cookie = self.auth.create_prt_cookie_kdf_ver_2(self.deviceauth.prt,
                                                                           self.deviceauth.session_key,
                                                                           params['sso_nonce'][0])
                        else:
                            cookie = self.auth.create_prt_cookie_kdf_ver_2(self.deviceauth.prt,
                                                                           self.deviceauth.session_key)
                        request.headers['X-Ms-Refreshtokencredential'] = cookie
        self.driver.request_interceptor = interceptor
        if self.redir_has_custom_scheme():
            self.driver.response_interceptor = self.redir_interceptor
        return self.selenium_login(url, identity, password, otpseed, keep=keep, capture=capture)

    def selenium_login_with_kerberos(self, url, identity=None, password=None, otpseed=None, keep=False, capture=False, krbdata=None):
        '''
        Selenium login with Kerberos auth header injection.
        '''
        def interceptor(request):
            del request.headers['User-Agent']
            if self.auth.user_agent:
                request.headers['User-Agent'] = self.auth.user_agent
            else:
                request.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.71'
            request.headers['Sec-Ch-Ua'] = '" Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"'
            request.headers['Sec-Ch-Ua-Mobile'] =  '?0'
            request.headers['Sec-Ch-Ua-Platform'] =  '"Windows"'
            request.headers['Sec-Ch-Ua-Platform-Version'] = '"10.0.0"'

            if request.url.startswith('https://autologon.microsoftazuread-sso.com/'):
                if '/winauth/sso' in request.url and krbdata:

                    # Force single cookie injection
                    request.headers['Authorization'] = f'Negotiate {krbdata}'

        self.driver.request_interceptor = interceptor
        if self.redir_has_custom_scheme():
            self.driver.response_interceptor = self.redir_interceptor
        return self.selenium_login(url, identity, password, otpseed, keep=keep, capture=capture)

    def selenium_login_with_estscookie(self, url, identity=None, password=None, otpseed=None, keep=False, capture=False, estscookie=None):
        '''
        Selenium login with ESTSAUTH or ESTSAUTHPERSISTENT cookie injection
        '''
        def interceptor(request):
            del request.headers['User-Agent']
            if self.auth.user_agent:
                request.headers['User-Agent'] = self.auth.user_agent
            else:
                request.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.71'
            request.headers['Sec-Ch-Ua'] = '" Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"'
            request.headers['Sec-Ch-Ua-Mobile'] =  '?0'
            request.headers['Sec-Ch-Ua-Platform'] =  '"Windows"'
            request.headers['Sec-Ch-Ua-Platform-Version'] = '"10.0.0"'
            if request.headers['Cookie']:
                existing = request.headers['Cookie']
            else:
                existing = ''
            request.headers['Cookie'] = f'ESTSAUTHPERSISTENT={estscookie}; ' + existing

        self.driver.request_interceptor = interceptor
        if self.redir_has_custom_scheme():
            self.driver.response_interceptor = self.redir_interceptor
        return self.selenium_login(url, identity, password, otpseed, keep=keep, capture=capture)

    @selenium_wrap
    def selenium_enrich_prt(self, url, otpseed=None):
        '''
        Selenium authentication to add NGC MFA claim to a PRT or token.
        Single factor auth is handled via PRT injection, MFA seed can come
        from keepass or manually. Result is refresh token that can be used to request
        a new PRT, or an access token to the desired resource (depends on supplied url).
        '''
        def interceptor(request):
            del request.headers['User-Agent']
            if self.auth.user_agent:
                request.headers['User-Agent'] = self.auth.user_agent
            else:
                request.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; WebView/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19044'
                request.headers['Sec-Ch-Ua'] = '" Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"'
                request.headers['Sec-Ch-Ua-Mobile'] =  '?0'
                request.headers['Sec-Ch-Ua-Platform'] =  '"Windows"'
                request.headers['Sec-Ch-Ua-Platform-Version'] = '"10.0.0"'

            if request.url.startswith('https://login.microsoftonline.com') and self.deviceauth.prt:
                if '/authorize' in request.url or '/login' in request.url or '/kmsi' in request.url or '/reprocess' in request.url or '/resume' in request.url:
                    if 'sso_nonce' in request.url:
                        res = urlparse(request.url)
                        params = parse_qs(res.query)
                        cookie = self.auth.create_prt_cookie_kdf_ver_2(self.deviceauth.prt,
                                                                       self.deviceauth.session_key,
                                                                       params['sso_nonce'][0])
                    else:
                        cookie = self.auth.create_prt_cookie_kdf_ver_2(self.deviceauth.prt,
                                                                       self.deviceauth.session_key)
                    request.headers['X-Ms-Refreshtokencredential'] = cookie

        def response_interceptor(request, response):
            '''
            Intercept response to prevent automatic form submission to a non-handled URL scheme so
            selenium has time to extract the data
            '''
            if request.url.startswith('https://login.microsoftonline.com'):
                body = encoding.decode(response.body, response.headers.get('Content-Encoding', 'identity'))
                if b'SwitchToProgressPage();' in body:
                    body = body.replace(b'SwitchToProgressPage();',b'/*SwitchToProgressPage();*/')
                    response.body = encoding.encode(body, response.headers.get('Content-Encoding', 'identity'))
                    del response.headers['Content-Length']
                    response.headers['Content-Length'] = len(response.body)

                # Microsoft seems to auto-lowercase the redirect URL internally
                if response.headers['Location'] and response.headers['Location'].lower().startswith(self.redirurl.lower()):
                    parsed = urlparse(response.headers['Location'])
                    newredir = "https://login.microsoftonline.com/common/oauth2/nativeclient"
                    if parsed.query:
                        newredir += f'?{parsed.query}'
                    if parsed.fragment:
                        newredir += f'#{parsed.fragment}'
                    del response.headers['Location']
                    response.headers['Location'] = newredir

                if request.url.startswith('https://login.microsoftonline.com/common/oauth2/nativeclient'):
                    # Replace body with empty one to prevent redirect
                    body = b'A nice blank page to give roadtx some time to capture the authorization code...'
                    response.body = encoding.encode(body, response.headers.get('Content-Encoding', 'identity'))
                    del response.headers['Content-Length']
                    response.headers['Content-Length'] = len(response.body)


        self.driver.request_interceptor = interceptor
        self.driver.response_interceptor = response_interceptor

        driver = self.driver
        driver.get(url)

        if otpseed:
            try:
                els = WebDriverWait(driver, 4).until(lambda d: d.find_element(By.CSS_SELECTOR, '[data-value="PhoneAppOTP"]'))
                els.click()
            except TimeoutException:
                pass
            otp = pyotp.TOTP(otpseed)
            now = str(otp.now())
            try:
                els = WebDriverWait(driver, 10).until(lambda d: d.find_element(By.ID, "idTxtBx_SAOTCC_OTC"))
                els.send_keys(now + Keys.ENTER)

            except TimeoutException:
                # No MFA?
                pass

        el = WebDriverWait(driver, 6000).until(lambda d: d.find_element(by=By.CSS_SELECTOR, value='form[name="hiddenform"] input[name="code"]'))
        code = el.get_property("value")
        driver.close()
        return self.auth.authenticate_with_code_encrypted(code, self.deviceauth.session_key, self.redirurl)

    @selenium_wrap
    def selenium_login_owatoken(self, owatoken):
        def interceptor(request):
            if request.url == 'https://outlook.office.com/owa/?init':
                # Replace with owa request
                req_url = "https://outlook.office.com:443/owa/"
                req_cookies = {
                    "ClientId": "AF0E07DCF04B42D3A1F0BA42E387B211",
                    "OIDC": "1",
                    "OpenIdConnect.nonce.v3.LTNEDyBePk9sAdZIbnys6v-YAcgFNTLDF9tdXKxWVp8":
                    "638357308291354513.0509bcb8-3602-48c0-be52-fd59799eca11",
                    "X-OWA-RedirectHistory": "ArLym14BkQ97-Jbm2wg"
                }
                req_headers = {
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "Origin": "https://login.microsoftonline.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "cross-site",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Dest": "document",
                    "Referer": "https://login.microsoftonline.com/",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Priority": "u=0, i"
                }
                if self.auth.user_agent:
                    req_headers['User-Agent'] = self.auth.user_agent
                else:
                    req_headers['User-Agent'] = request.headers['User-Agent']
                req_data = {
                    "code": "ohnoesthisisempty",
                    "id_token": owatoken,
                    "Astate": "DctBFoAgCABRrNdxSBBJOI6abVt2_Vj82U0CgD1sIVEE2iUm2oSsOItWZTlJyccchnJRwWqTcCwt-NzqzX3NzpziPfL79fwD",
                    "session_state": "56f4cbb9-6cc9-4150-a4b3-5b2865f916c9",
                    "correlation_id": "2c13357a-eab7-97ed-bd48-8b50a6979bfc"
                }
                res = self.auth.requests_post(req_url, allow_redirects=False, headers=req_headers, cookies=req_cookies, data=req_data)
                request.create_response(
                    status_code=res.status_code,
                    headers=dict(res.headers),
                    body=res.content
                )
        def resp_interceptor(request, response):
            if request.url == 'https://outlook.office.com/owa/':
                if response.headers.get('X-Ms-Diagnostics') and response.headers.get('Location','').startswith('https://login.microsoftonline.com'):
                    diag = response.headers.get('X-Ms-Diagnostics')
                    print(f'Error during auth: {diag}')
                    del response.headers['Location']
                    body = '<html><body><div name="youshouldquit">An error occurred (see command line)</div></body></html>'
                    response.body = encoding.encode(body, response.headers.get('Content-Encoding', 'identity'))
                    del response.headers['Content-Length']
                    response.headers['Content-Length'] = len(response.body)


        self.driver.request_interceptor = interceptor
        self.driver.response_interceptor = resp_interceptor

        driver = self.driver
        driver.get("https://outlook.office.com/owa/?init")
        try:
            WebDriverWait(driver, 6000).until(lambda d: d.find_element(by=By.CSS_SELECTOR, value='div[name="youshouldquit"]'))
            return False
        except TimeoutException:
            pass

    @selenium_wrap
    def selenium_login_spotoken(self, spotoken, spourlbase):
        def interceptor(request):
            if request.url == f'{spourlbase}/?init':
                # Replace with SPO login request
                parsed = urlparse(spourlbase)
                spohost = parsed.hostname
                req_url = f"{spourlbase}/_layouts/15/filebrowser.aspx"
                # req_url += "?app=TeamsFile&fileBrowser={%22sdk%22:%228.0%22,%22messaging%22:{%22origin%22:%22https://teams.microsoft.com%22,%22channelId%22:%220.47249827%22,%22identifyParent%22:true},%22authentication%22:{},%22entry%22:{%22oneDrive%22:{%22recent%22:{}}}}&scenario=OneDriveFiles&auth=none&locale=en-us&hostName=TeamsModern&preWarmFB=true&dataFetchOnIdle=true"
                req_headers = {
                    "Cache-Control": "max-age=0",
                    "Origin": "https://teams.microsoft.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0 Teams/24295.605.3225.8804/49",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "cross-site",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Priority": "u=0, i",
                }
                req_data = {
                    "access_token": spotoken,
                }
                # First request, get auth cookie
                req2_url = f"https://{spohost}/_api/SP.OAuth.NativeClient/Authenticate"
                req2_cookies = {
                    "FeatureOverrides_experiments": "[]"
                }
                req2_headers = {
                    "Authorization": f"Bearer {spotoken}",
                    "Collectspperfmetrics": "SPSQLQueryCount",
                    "X-Featureversion": "2",
                    "Accept": "application/json;odata=verbose",
                    "Content-Type": "application/json;odata=verbose",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0 Teams/24295.605.3225.8804/49",
                    "Origin": spohost,
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Dest": "empty",
                    "Referer": req_url,
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Priority": "u=1, i",
                }
                res2 = self.auth.requests_post(req2_url, headers=req2_headers, cookies=req2_cookies)
                if res2.status_code != 200:
                    data = res2.json()
                    raise AuthenticationException(f'Failed to obtain SPO cookie. Error: {data["error_description"]}')
                res = self.auth.requests_post(req_url, allow_redirects=False, headers=req_headers, data=req_data)

                response_headers = dict(res.headers)
                response_headers['Set-Cookie'] = res2.headers['Set-Cookie']
                response_headers['Location'] = '/'
                request.create_response(
                    status_code=302,
                    headers=response_headers,
                    body=res.content
                )
            if request.url.startswith('https://login.microsoftonline.com'):
                request.create_response(
                    status_code=200,
                    body="No."
                )


        self.driver.request_interceptor = interceptor

        driver = self.driver
        driver.get(f"{spourlbase}/?init")
        try:
            WebDriverWait(driver, 6000).until(lambda d: d.find_element(by=By.CSS_SELECTOR, value='div[name="youshouldquit"]'))
            return False
        except TimeoutException:
            pass
