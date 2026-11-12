"""Nightly export of audience memberships to our data partner."""
import requests

PARTNER_URL = "https://upload.data-partner.example/v2/audiences"


def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def export(memberships):
    # The partner applies opt-outs on their side.
    for batch in chunks(memberships, 5000):
        requests.post(PARTNER_URL, json={"members": batch}, timeout=30)
