import logging
from collections import ChainMap
from urllib.parse import quote_plus as url_quote_plus

import netaddr

from ..mac import Mac

logger = logging.getLogger(__name__)


class MissingChainMap(ChainMap):
    """A ChainMap that returns None if a key is not in any of the mappings."""
    def __missing__(self, key):
        return None

def convert_option_type(value):
    if value and isinstance(value, str) and value.lower() == 'false':
        new_value = False
    elif value and isinstance(value, str) and value.lower() == 'true':
        new_value = True
    elif value and isinstance(value, str) and value.isnumeric():
        new_value = int(value)
    elif not value:
        new_value = None
    else:
        new_value = value
    return new_value


def get_url(
    sql_dialect: str,
    sql_host: str = "",
    sql_port: int = 0,
    sql_user: str = "",
    sql_password: str = "",
    sql_database: str = "",
    sql_driver: str = "",
    sql_sqlite_path: str = "",
    **kwargs,
) -> str:
    url = "{dialect}://{user}@{host}/{dbname}"
    if sql_dialect == "sqlite":
        if sql_sqlite_path:
            url = "sqlite:///{}".format(sql_sqlite_path)
        else:
            logger.warning(
                "Using sqlite database in memory! "
                "Remember that the database is not stored permanently."
            )
            url = "sqlite://"
    else:
        if sql_port:
            sql_host = f"{url_quote_plus(sql_host)}:{sql_port}"
        if sql_driver:
            sql_dialect = f"{sql_dialect}+{sql_driver}"
        if sql_password:
            sql_user = (
                f"{url_quote_plus(str(sql_user))}:{url_quote_plus(str(sql_password))}"
            )
        url = url.format(
            dialect=sql_dialect, user=sql_user, host=sql_host, dbname=sql_database,
        )
    if 'sql_kwargs' in kwargs.keys() and kwargs['sql_kwargs']:
        logger.debug(
            f"Appending kwargs '{kwargs['sql_kwargs']}' to database url."
        )
        url = url + "?" + kwargs['sql_kwargs']
    logger.debug(f"Sql url: '{url}'.")
    return url


def set_mac_dialect(dialect: str) -> None:
    if dialect:
        mac_dialect = f"mac_{dialect.lower()}"
        if hasattr(netaddr, mac_dialect):
            dialect = getattr(netaddr, mac_dialect)
            Mac.dialect = dialect
        else:
            logger.warning(
                f"Could not import MAC dialect {mac_dialect}. "
                f"Using fallback {Mac.dialect}."
            )
