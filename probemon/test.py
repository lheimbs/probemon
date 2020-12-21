import click
import paho.mqtt.client as mqtt_client


class Mqtt(object):
    def __init__(self, host="localhost", port=1883):
        self._client = mqtt_client.Client()
        self.__host = host
        self.__port = port

    def set_server(self, host, port):
        self.__host = host
        self.__port = port

    def set_user(self, user, password):
        self._client.username_pw_set(user, password)

    def set_tls(self, ca_certs, certfile, keyfile):
        self._client.tls_set(ca_certs=ca_certs, certfile=certfile, keyfile=keyfile)


@click.group()
@click.version_option()
def cli():
    pass  # Entry Point

@cli.group()
@click.pass_context
def mqtt(ctx):
    print(f"Make object Mqtt.")
    ctx.obj = Mqtt()

@mqtt.command('server')
@click.option('--host', '-h', default='localhost')
@click.option('--port', '-p', default=1883)
@click.pass_obj
def mqtt_server(ctx, host, port):
    print(f"Set host='{host}' and port='{port}'")
    ctx.set_server(host, port)

@mqtt.command('auth')
@click.argument('user')
@click.argument('password')
@click.pass_obj
def mqtt_auth(ctx, user, password):
    print(f"Set Mqtt user to '{user}' and password to '{password}'")
    ctx.set_user(user, password)

@mqtt.command('tls')
@click.option('--ca_certs')
@click.option('--certfile')
@click.option('--keyfile')
@click.pass_obj
def mqtt_tls(ctx, ca_certs, certfile, keyfile):
    print(f"Set mqtt tls with ca_certs='{ca_certs}', certfile='{certfile}' and keyfile='{keyfile}'")
    ctx.set_tls(ca_certs, certfile, keyfile)

# @cloudflare_record.command('add')
# @click.option('--ttl', '-t')
# @click.argument('domain')
# @click.argument('name')
# @click.argument('type')
# @click.argument('content')
# @click.pass_obj
# def cloudflare_record_add(ctx, domain, name, type, content, ttl):
#     pass

# @cloudflare_record.command('edit')
# @click.option('--ttl', '-t')
# @click.argument('domain')
# @click.argument('name')
# @click.argument('type')
# @click.argument('content')
# @click.pass_obj
# def cloudflare_record_edit(ctx, domain):
#     pass

@cli.group()
@click.pass_context
def uptimerobot(ctx):
    pass

@uptimerobot.command('add')
@click.option('--alert', '-a', default=True)
@click.argument('name')
@click.argument('url')
@click.pass_obj
def uptimerobot_add(ctx, name, url, alert):
    pass

@uptimerobot.command('delete')
@click.argument('names', nargs=-1, required=True)
@click.pass_obj
def uptimerobot_delete(ctx, names):
    pass

if __name__ == "__main__":
    cli()
