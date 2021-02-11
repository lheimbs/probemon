
def get_cli_params(params: dict):
    mqtt = {}
    sql = {}
    app = {}
    for key, value in params.items():
        if not value:
            value = None

        if key.startswith('mqtt_'):
            mqtt[key.replace('mqtt_', '')] = value
        elif key.startswith('sql_'):
            sql[key.replace('sql_', '')] = value
        else:
            app[key] = value
    return app, mqtt, sql
