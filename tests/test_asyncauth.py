from roadtools.roadlib.asyncauth import AsyncAuthentication
from roadtools.roadlib.asyncdeviceauth import AsyncDeviceAuthentication
import pytest
import os
import asyncio

def test_async_authentication():
    auth = AsyncAuthentication()
    auth.username = os.environ.get("rtuser")
    auth.password = os.environ.get("rtpass")
    assert auth.username is not None and auth.password is not None
    auth.tenant = os.environ.get("rtuser").split('@')[1]
    asyncio.run(get_async_tokens(auth))

async def get_async_tokens(auth):
    jobs = [
        auth.user_discovery_v1(os.environ.get("rtuser")),
        auth.user_discovery_v2(os.environ.get("rtuser")),
        auth.authenticate_username_password_native(),
        auth.get_srv_challenge_nonce()
    ]
    jobs.append(auth.authenticate_with_desktopsso_token(await auth.get_desktopsso_token(os.environ.get("rtuser"), os.environ.get("rtpass"))))
    await asyncio.gather(*jobs)
    auth.scope = 'openid offline_access'
    tokens = await auth.authenticate_username_password_native_v2(returnreply=True)
    assert 'refresh_token' in tokens
    refresh_token = tokens['refresh_token']
    jobs = [
        auth.authenticate_with_refresh_native(refresh_token),
        auth.authenticate_with_refresh_native_v2(refresh_token)
    ]
    await asyncio.gather(*jobs)
    await auth.close_session()
