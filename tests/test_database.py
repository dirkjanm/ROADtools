from roadtools.roadrecon.server import create_app_test, db
from sqlalchemy import func
from roadtools.roadlib.metadef.database import Policy
from flask_sqlalchemy import SQLAlchemy
import pytest
import roadtools.roadlib.metadef.database as database
import os

@pytest.fixture(scope='module')
def _db():
    '''
    Provide the transactional fixtures with access to the database via a roadlib
    database connection.
    '''
    session = database.get_session(database.init(dburl='sqlite:///' + os.path.join(os.getcwd(), 'roadrecon.db')))
    return session

def test_has_policies(_db):
    numpolicies = _db.query(func.count(Policy.objectId)).where(Policy.policyType == 18).scalar()
    assert numpolicies > 5
