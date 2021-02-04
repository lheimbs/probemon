import logging
import sqlalchemy
from sqlalchemy.orm.session import Session
from contextlib import contextmanager

logger = logging.getLogger('sql')

class Sql:
    """ Class representing the sql connection """

    def __init__(self, enabled=False):
        self._engine = None
        self.__enabled = enabled

    # def enable(self):
    #     self.__enabled = True

    def is_enabled(self):
        return self.__enabled

    def set_url(self, url):
        try:
            self._engine = sqlalchemy.create_engine(url)
            self.__enabled = True
        except ModuleNotFoundError:
            logger.exception(
                "Could not create sql connection because a neccessary python module is missing."
            )
            self._engine = None

    def register_engine(self, Session):
        if self._engine is not None:
            Session.configure(bind=self._engine)
            self.__enabled = True
        else:
            logger.error(
                "Can't configure Sql-Session because the engine is not configured. "
                "Disabling sql!"
            )
            self.__enabled = False


@contextmanager
def session_scope():
    """Provide a transactional scope around a series of operations."""
    session = Session()
    try:
        yield session
        session.commit()
    except:         # noqa: E722
        logger.exception("Exception occured during sql operation!")
        session.rollback()
        raise
    finally:
        session.close()
