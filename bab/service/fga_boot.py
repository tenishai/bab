"""Boot against OpenFGA with nothing pre-provisioned: find or create the store by
name, write the model generated from the catalogue, hand back both ids.

The DSL to JSON step uses the `fga` CLI (pinned in the image); the SDK only
speaks JSON. Writing the same model twice yields a new id for the same
content, which is harmless: checks pin the id this boot received.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile

from bab import model
from bab.catalogue import Catalogue

log = logging.getLogger(__name__)


class BootError(RuntimeError):
    pass


def model_json(cat: Catalogue, fga_bin: str | None = None) -> dict:
    fga = fga_bin or shutil.which("fga") or "./fga"
    with tempfile.NamedTemporaryFile("w", suffix=".fga", delete=False) as fh:
        fh.write(model.generate(cat))
        path = fh.name
    out = subprocess.run([fga, "model", "transform", "--file", path], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise BootError(f"fga model transform failed: {out.stderr.strip() or out.stdout.strip()}")
    return json.loads(out.stdout)


def ensure_store_and_model(api_url: str, cat: Catalogue, store_name: str = "bab", api_token: str | None = None,
                           fga_bin: str | None = None, client=None) -> tuple[str, str]:
    """(store_id, model_id) for this boot. `client` is an OpenFgaClient-like object (tests pass a fake)."""
    if client is None:
        from openfga_sdk import ClientConfiguration
        from openfga_sdk.sync import OpenFgaClient

        cfg = ClientConfiguration(api_url=api_url)
        if api_token:
            from openfga_sdk.credentials import CredentialConfiguration, Credentials

            cfg.credentials = Credentials(method="api_token",
                                          configuration=CredentialConfiguration(api_token=api_token))
        client = OpenFgaClient(cfg)
    try:
        stores = client.list_stores().stores or []
        match = [s for s in stores if s.name == store_name]
        store_id = match[0].id if match else client.create_store({"name": store_name}).id
        client.set_store_id(store_id)
        body = model_json(cat, fga_bin)
        model_id = client.write_authorization_model(body).authorization_model_id
    except BootError:
        raise
    except Exception as exc:
        raise BootError(f"OpenFGA at {api_url}: {exc}") from exc
    log.info("openfga store %s (%s) model %s", store_name, store_id, model_id)
    return store_id, model_id
