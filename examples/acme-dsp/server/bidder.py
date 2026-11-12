"""Builds OpenRTB bid requests to exchanges."""
import requests

EXCHANGE_URL = "https://bid.exchange-one.example/openrtb2"


def build_request(ctx):
    req = {
        "id": ctx.request_id,
        "device": {"geo": {"lat": ctx.lat, "lon": ctx.lon, "type": 1}},
        "user": {"id": ctx.user_id},
        "regs": {"ext": {"gpc": 1 if ctx.headers.get("Sec-GPC") == "1" else 0}},
    }
    return req


def send(ctx):
    sale_allowed = ctx.headers.get("Sec-GPC") != "1" and not ctx.opted_out
    if sale_allowed:
        return requests.post(EXCHANGE_URL, json=build_request(ctx), timeout=0.12)
    return None
