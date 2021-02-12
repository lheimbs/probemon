import logging
from typing import TypeVar

import sqlalchemy
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
# from contextlib import contextmanager

from ..ProbeRequest import Base

logger = logging.getLogger('sql')
Session = TypeVar('Session')
ProbeRequest = TypeVar('ProbeRequest')

class Sql:
    """ Class representing the sql connection """
    __enabled = False

    def enable():
        Sql.__enabled = True

    def disable():
        Sql.__enabled = False

    def is_enabled():
        return Sql.__enabled

    def publish_probe(probe: ProbeRequest, Session_cls: Session) -> None:
        if Sql.is_enabled() and Session_cls is not None:
            probe_model = probe.model()
            if probe_model:
                session = Session_cls()
                try:
                    session.add(probe_model)
                    session.commit()
                except:         # noqa: E722
                    logger.exception("Exception occured during sql operation!")
                    session.rollback()
                    raise
                finally:
                    session.close()

    def __init__(self):
        self._engine = None

    def set_url(self, url):
        try:
            if url == 'sqlite://':
                self._engine = sqlalchemy.create_engine(
                    url, connect_args={'check_same_thread': False},
                    poolclass=StaticPool,
                )
            else:
                self._engine = sqlalchemy.create_engine(url)
            Sql.enable()
        except ModuleNotFoundError:
            logger.exception(
                "Could not create sql connection because "
                "a neccessary python module is missing."
            )
            self._engine = None

    def register(self) -> Session:
        Session_cls = None
        if self._engine is not None and Sql.is_enabled():
            logger.debug("Making sql metadata...")
            Base.metadata.create_all(self._engine)
            logger.debug("Getting sql scoped session...")
            Session_cls = scoped_session(sessionmaker(bind=self._engine))
        else:
            logger.warning(
                "Can't configure Sql-Session because "
                "the engine is not configured. "
                "Disabling sql!"
            )
            Sql.disable()
        return Session_cls
