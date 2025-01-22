import os
import codecs
import json
def find_redirurl_for_client(client, interactive=True, broker=False):
    '''
    Get valid redirect URLs for specified client. Interactive means a https URL is preferred.
    In practice roadtx often prefers non-interactive URLs even with interactive flows since it rewrites
    the URLs on the fly anyway
    '''
    current_dir = os.path.abspath(os.path.dirname(__file__))
    datafile = os.path.join(current_dir, 'firstpartyscopes.json')
    with codecs.open(datafile,'r','utf-8') as infile:
        data = json.load(infile)
    try:
        app = data['apps'][client.lower()]
    except KeyError:
        return 'https://login.microsoftonline.com/common/oauth2/nativeclient'
    if broker:
        brokerurl = f'ms-appx-web://Microsoft.AAD.BrokerPlugin/{client.lower()}'
        if brokerurl in app['redirect_uris']:
            return brokerurl
        return app['preferred_noninteractive_redirurl']
    if interactive and app['preferred_interactive_redirurl'] is not None:
        return app['preferred_interactive_redirurl']
    if app['preferred_noninteractive_redirurl']:
        return app['preferred_noninteractive_redirurl']
    # Return default URL even if it might not work since some follow up functions break when called with a None value
    return 'https://login.microsoftonline.com/common/oauth2/nativeclient'
