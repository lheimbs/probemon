
def get_cli_params(params: dict) -> dict:
    cfg = {}
    for key, value in params.items():
        if value:
            cfg[key] = value
    return cfg
