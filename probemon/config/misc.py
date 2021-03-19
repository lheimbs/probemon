import logging
from urllib.parse import quote_plus as url_quote_plus

logger = logging.getLogger(__name__)


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
    user: str,
    password: str,
    host: str,
    port: int,
    database: str,
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
