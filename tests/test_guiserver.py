from roadtools.roadrecon.server import create_app_test, db
from sqlalchemy import func
from roadtools.roadlib.metadef.database import Policy
from flask_sqlalchemy import SQLAlchemy

import pytest

@pytest.fixture(scope='module')
def app():
    app = create_app_test()
    return app

def test_db_has_users(client):
    """Test if there are users in the db"""

    rv = client.get('/api/users')
    assert len(rv.json) > 5
    for user in rv.json:
        assert user['userPrincipalName'] is not None
        assert user['objectId'] is not None

def test_db_has_devices(client):
    """Test if there are devices in the db"""

    rv = client.get('/api/devices')
    assert len(rv.json) > 5
    for device in rv.json:
        assert device['deviceId'] is not None
        assert device['objectId'] is not None

def test_db_has_devices_owners(client):
    """Test if there are devices with an owner in the db"""

    rv = client.get('/api/devices')
    assert len(rv.json) > 5
    owners = 0
    for device in rv.json:
        ddata = client.get('/api/devices/' + device['objectId'])
        ddata_json = ddata.json
        owners += len(ddata_json['owner'])
        for owner in ddata_json['owner']:
            assert 'displayName' in owner

    assert owners > 0

def test_sp_links_work(client):
    """Test if the ServicePrincipal links work"""

    rv = client.get('/api/serviceprincipals')
    assert len(rv.json) > 5
    outlinks = 0
    for sp in rv.json:
        ddata = client.get('/api/serviceprincipals/' + sp['objectId'])
        ddata_json = ddata.json
        outlinks += len(ddata_json['oauth2PermissionGrants'])
        for owner in ddata_json['oauth2PermissionGrants']:
            assert 'resourceId' in owner
        outlinks += len(ddata_json['appRolesAssigned'])
        for owner in ddata_json['appRolesAssigned']:
            assert 'principalId' in owner
    assert outlinks > 0
