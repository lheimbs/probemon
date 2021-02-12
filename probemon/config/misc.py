import re
import logging
from hashlib import sha3_256
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
    sqlite_path: str = "",
    **kwargs,
):
    url = "{dialect}://{user}@{host}/{dbname}"
    if dialect == "sqlite":
        url = "sqlite:///{}"
        if sqlite_path:
            url = url.format(sqlite_path)
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
            user = f"{url_quote_plus(str(user))}:{url_quote_plus(str(password))}"
        url = url.format(dialect=dialect, user=user, host=host, dbname=database)
    if 'kwargs' in kwargs.keys() and kwargs['kwargs']:
        logger.debug(f"Appending kwargs '{kwargs['kwargs']}' to database url.")
        url = url + "?" + kwargs['kwargs']
    logger.debug(f"Sql url: '{url}'.")
    return url


class RedactingFilter(logging.Filter):
    def filter(self, record):
        # print(record.msg)
        # print(self.redact(record.msg))
        record.msg = self.redact(record.msg)
        if isinstance(record.args, dict):
            for k in record.args.keys():
                record.args[k] = self.redact(record.args[k])
        else:
            record.args = tuple(self.redact(arg) for arg in record.args)
        return True

    def replace_pwd(self, match_object):
        # print(match_object.group("pwd"))
        if match_object.group("pwd"):
            hashed_pwd = sha3_256(match_object.group("pwd").encode()).hexdigest()
            return match_object[0].replace(match_object.group('pwd'), hashed_pwd)
        return match_object[0]

    def redact(self, msg):
        msg = str(msg)
        return re.sub(r'(?:(\w+):\/\/(.*?):)(?P<pwd>.*?)(?:\@(.*?):(.*?)\/(\w+))', self.replace_pwd, msg)


class RedactingFormatter(logging.Formatter):
    URL_PASSWORD = re.compile(r'(?:(\w+):\/\/(.*?):)(?P<pwd>.*?)(?:\@(.*?):(.*?)\/(\w+))')

    def replace_pwd(self, match_object):
        # print(match_object.group("pwd"))
        if match_object.group("pwd"):
            hashed_pwd = sha3_256(match_object.group("pwd").encode()).hexdigest()
            return match_object[0].replace(match_object.group('pwd'), hashed_pwd)
        return match_object[0]

    def format(self, msg):
        password_match = self.URL_PASSWORD.search(msg)
        redacted_message = super().format(record=msg)

        if password_match:
            redacted_message = self.URL_PASSWORD.sub(self.replace_pwd, redacted_message)
        return redacted_message
