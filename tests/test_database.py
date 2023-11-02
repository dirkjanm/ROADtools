from roadtools.roadrecon.server import create_app_test, db
from sqlalchemy import func
from roadtools.roadlib.metadef.database import Policy
from flask_sqlalchemy import SQLAlchemy
import pytest


@pytest.fixture(scope='session')
def _db(app):
    '''
    Provide the transactional fixtures with access to the database via a Flask-SQLAlchemy
    database connection.
    '''
    db = SQLAlchemy(app=app)

    return db

@pytest.fixture(scope='session')
def app():
    app = create_app_test()
    return app

def test_has_policies(app, _db):
    with app.app_context():
        numpolicies = _db.session.query(func.count(Policy.objectId)).where(Policy.policyType == 18).scalar()
    assert numpolicies > 5
