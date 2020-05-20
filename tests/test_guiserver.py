from roadtools.roadrecon.server import create_app_test
import pytest

@pytest.fixture
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
