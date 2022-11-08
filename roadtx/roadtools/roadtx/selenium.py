import os
import sys
from urllib.parse import urlparse, parse_qs, quote_plus
from roadtools.roadlib.auth import Authentication, AuthenticationException, get_data, WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadtx.keepass import HackyKeePassFileReader
from seleniumwire import webdriver as webdriver_wire
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException
import pyotp

class SeleniumAuthentication():
    def __init__(self, auth, deviceauth, redirurl, proxy=None):
        self.proxy = proxy
        self.auth = auth
        self.deviceauth = deviceauth
        self.driver = None
        self.redirurl = redirurl

    def get_service(self, driverpath):
        # Default expects geckodriver to be in path, but if it exists locally we use that
        if driverpath == 'geckodriver' and os.path.exists(driverpath):
            driverpath = './geckodriver'
        # Try to find the driver if a path is given
        if driverpath != 'geckodriver' and not os.path.exists(driverpath):
            print('geckodriver not found! Required for selenium operation. Please download from https://github.com/mozilla/geckodriver/releases')
            return False
        service = Service(executable_path=driverpath)
        return service

    def get_webdriver(self, service, intercept=False):
        '''
        Load webdriver based on service, which is either
        from selenium or selenium-wire if interception is requested
        '''
        if self.proxy:
            options = {
                'proxy': {
                    'http': f'http://{self.proxy}',
                    'https': f'https://{self.proxy}',
                    'no_proxy': 'localhost,127.0.0.1'
                }
            }
        else:
            options = {}
        if intercept:
            driver = webdriver_wire.Firefox(service=service, seleniumwire_options=options)
        else:
            driver = webdriver.Firefox(service=service)
        return driver

    def get_keepass_cred(self, identity, filepath, password):
        '''
        Get identity from KeePass file
        '''
        if not password and 'KPPASS' in os.environ:
            password = os.environ['KPPASS']

        if filepath.endswith('.xml'):
            reader = HackyKeePassFileReader(filepath, password, plain=True)
        else:
            reader = HackyKeePassFileReader(filepath, password, plain=False)
        entry = reader.get_entry(identity)
        if not entry:
            raise AuthenticationException(f'Specified username {identity} not found in KeePass file')
        userpassword = entry['Password']
        otpseed = entry['otp']
        return userpassword, otpseed

    def selenium_login(self, url, identity=None, password=None, otpseed=None, keep=False):
        '''
        Selenium based login with optional autofill of whatever is provided
        '''
        driver = self.driver
        driver.get(url)
        if identity and not 'login_hint' in url:
            el = WebDriverWait(driver, 3000).until(lambda d: d.find_element(By.ID, "i0116"))
            el.send_keys(identity + Keys.ENTER)
        if password:
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
            WebDriverWait(driver, 2).until(lambda d: '?code=' in d.current_url)
            res = urlparse(driver.current_url)
            params = parse_qs(res.query)
            code = params['code'][0]
            if not keep:
                driver.close()
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

        try:
            WebDriverWait(driver, 120).until(lambda d: '?code=' in d.current_url)
            res = urlparse(driver.current_url)
            params = parse_qs(res.query)
            code = params['code'][0]
            if not keep:
                driver.close()
            return self.auth.authenticate_with_code_native(code, self.redirurl)
        except TimeoutException:
            if not keep:
                driver.close()
                raise AuthenticationException('Authentication did not complete within time limit')
        return False

    def selenium_login_with_prt(self, url, identity=None, password=None, otpseed=None, keep=False):
        '''
        Selenium login with PRT injection.
        '''
        def interceptor(request):
            del request.headers['User-Agent']
            request.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 Edg/103.0.1264.71'
            request.headers['Sec-Ch-Ua'] = '" Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"'
            request.headers['Sec-Ch-Ua-Mobile'] =  '?0'
            request.headers['Sec-Ch-Ua-Platform'] =  '"Windows"'
            request.headers['Sec-Ch-Ua-Platform-Version'] = '"10.0.0"'

            if request.url.startswith('https://login.microsoftonline.com'):
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
        self.driver.request_interceptor = interceptor
        return self.selenium_login(url, identity, password, otpseed, keep=keep)

    def selenium_enrich_prt(self, url, otpseed=None):
        '''
        Selenium authentication to add NGC MFA claim to a PRT or token.
        Single factor auth is handled via PRT injection, MFA seed can come
        from keepass or manually. Result is refresh token that can be used to request
        a new PRT, or an access token to the desired resource (depends on supplied url).
        '''
        def interceptor(request):
            del request.headers['User-Agent']
            request.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; WebView/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19044'
            request.headers['Sec-Ch-Ua'] = '" Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"'
            request.headers['Sec-Ch-Ua-Mobile'] =  '?0'
            request.headers['Sec-Ch-Ua-Platform'] =  '"Windows"'
            request.headers['Sec-Ch-Ua-Platform-Version'] = '"10.0.0"'

            if request.url.startswith('https://login.microsoftonline.com'):
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
        self.driver.request_interceptor = interceptor

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
