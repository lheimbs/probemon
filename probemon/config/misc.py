import logging
from urllib.parse import quote_plus as url_quote_plus

logger = logging.getLogger('config.misc')

def get_url(
    dialect: str,
    user: str,
    password: str,
    host: str,
    port: int,
    database: str,
    driver: str = "",
    path: str = "",
):
    url = "{dialect}://{user}@{host}/{dbname}"
    if dialect == "sqlite":
        url = "sqlite:///{path}"
        if path:
            url = url.format(path)
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
            user = f"{url_quote_plus(user)}:{url_quote_plus(password)}"
        url = url.format(dialect=dialect, user=user, host=host, dbname=database)
    logger.debug(f"Sql url: '{url}'.")
    return url
