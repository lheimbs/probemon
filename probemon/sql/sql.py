import logging
from typing import TypeVar, Union

import sqlalchemy
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import NoSuchModuleError

from ..mac import Mac
from ..probe_request import Base, ProbeRequestModel

logger = logging.getLogger(__name__)
Session = TypeVar('Session')
ProbeRequest = TypeVar('ProbeRequest')

class Sql:
    """ Class representing the sql connection """
    _enabled: bool = False
    _Session: bool = None

    def __init__(self) -> None:
        self._engine = None

    def enable() -> None:
        Sql._enabled = True

    def disable() -> None:
        Sql._enabled = False

    def is_enabled() -> bool:
        return Sql._enabled

    def set_url(self, url: str) -> None:
        try:
            if url == 'sqlite://':
                self._engine = sqlalchemy.create_engine(
                    url, connect_args={'check_same_thread': False},
                    poolclass=StaticPool,
                )
            else:
                self._engine = sqlalchemy.create_engine(url)
            Sql.enable()
        except (ModuleNotFoundError, NoSuchModuleError):
            logger.exception(
                "Could not create sql connection because "
                "a neccessary python module is missing."
            )
            self._engine = None

    def register(self, drop_tables: bool = False) -> None:
        if self._engine is not None and Sql.is_enabled():
            logger.debug("Making sql metadata...")
            Base.metadata.create_all(self._engine)
            logger.debug("Getting sql scoped session...")
            Sql._Session = scoped_session(sessionmaker(bind=self._engine))
        else:
            logger.debug(
                "Can't configure Sql-Session because "
                "the engine is not configured. "
                "Disabling sql!"
            )
            Sql.disable()
            Sql._Session = None

    def publish_probe(probe: ProbeRequest) -> Union[ProbeRequestModel, None]:
        if Sql.is_enabled() and Sql._Session is not None:
            probe_model = probe.model()
            if probe_model:
                session = Sql._Session()
                try:
                    session.add(probe_model)
                    session.commit()
                except:         # noqa: E722
                    logger.exception(
                        "Exception occured during sql operation!"
                    )
                    session.rollback()
                    raise
                finally:
                    session.close()
                return probe_model
        return None

    def get_vendor(mac: Mac) -> str:
        if Sql.is_enabled() and Sql._Session is not None:
            session = Sql._Session()
            try:
                vendors = session.query(ProbeRequestModel.vendor).filter(
                    ProbeRequestModel.mac == str(mac)
                ).distinct()
                for vendor in vendors:
                    if vendor[0]:
                        return vendor[0]
            except:         # noqa: E722
                logger.exception(
                    "Exception occured during sql operation!"
                )
                session.rollback()
                raise
            finally:
                session.close()
        return ''
