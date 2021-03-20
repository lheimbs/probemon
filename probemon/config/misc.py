import logging
from collections import ChainMap
from urllib.parse import quote_plus as url_quote_plus

import netaddr

from ..mac import Mac

logger = logging.getLogger(__name__)


class IgnoreNoneChainMap(ChainMap):
    """A ChainMap that ignores None entries in the map.

    It allows defining defaults in cli options.
    Warning: does not work with defaultdict because of <key in mapping> usage!
    """
    def __missing__(self, key):
        return None

    def __getitem__(self, key):
        for mapping in self.maps:
            if key in mapping.keys() and mapping[key] is not None:
                return mapping[key]
        return self.__missing__(key)

    def get_all(self, key: str, ignore_none: bool = False) -> list:
        """Get all entries from all dicts that match key"""
        values = []
        for mapping in self.maps:
            if key in mapping.keys():
                if (ignore_none and mapping[key] is not None) \
                        or not ignore_none:
                    values.append(mapping[key])
        return values


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
    dialect: str,
    host: str = "",
    port: int = 0,
    user: str = "",
    password: str = "",
    database: str = "",
    driver: str = "",
    sqlite_path: str = "",
    **kwargs,
) -> str:
    url = "{dialect}://{user}@{host}/{dbname}"
    if dialect == "sqlite":
        if sqlite_path:
            url = "sqlite:///{}".format(sqlite_path)
        else:
            logger.warning(
                "Using sqlite database in memory! "
                "Remember that the database is not stored permanently."
            )
            url = "sqlite://"
    else:
        if port:
            host = f"{url_quote_plus(host)}:{port}"
        if driver:
            dialect = f"{dialect}+{driver}"
        if password:
            user = (
                f"{url_quote_plus(str(user))}:{url_quote_plus(str(password))}"
            )
        url = url.format(
            dialect=dialect, user=user, host=host, dbname=database,
        )
    if 'kwargs' in kwargs.keys() and kwargs['kwargs']:
        logger.debug(
            f"Appending kwargs '{kwargs['kwargs']}' to database url."
        )
        url = url + "?" + kwargs['kwargs']
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
