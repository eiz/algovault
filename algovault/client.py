import os
import sys
from typing import Optional

from algosdk import kmd
from algosdk.v2client import algod
import click
from os import path

ALGORAND_DATA = None
kcl: Optional[kmd.KMDClient]
kcl = None
acl: Optional[algod.AlgodClient]
acl = None


def _read_string_path(path):
    with open(path, "r") as f:
        return f.read().strip("\n")


def get_algod():
    assert acl is not None
    return acl


def get_kmd():
    assert kcl is not None
    return kcl


def init_environ():
    print("init environ")
    global kcl, acl, ALGORAND_DATA
    if not "ALGORAND_DATA" in os.environ:
        click.echo("ALGORAND_DATA environment variable must be set.", err=True)
        sys.exit(1)
    ALGORAND_DATA = os.environ["ALGORAND_DATA"]
    algod_net_path = path.join(ALGORAND_DATA, "algod.net")
    algod_token_path = path.join(ALGORAND_DATA, "algod.token")
    kmd_base_path = None
    for dir in os.listdir(ALGORAND_DATA):
        if dir.startswith("kmd-"):
            kmd_base_path = path.join(ALGORAND_DATA, dir)
    if not kmd_base_path:
        click.echo(
            "Could not find kmd directory in $ALGORAND_DATA. Make sure it's running."
        )
        sys.exit(1)
    kmd_net_path = path.join(kmd_base_path, "kmd.net")
    kmd_token_path = path.join(kmd_base_path, "kmd.token")
    algod_url = f"http://{_read_string_path(algod_net_path)}"
    algod_token = _read_string_path(algod_token_path)
    kmd_url = f"http://{_read_string_path(kmd_net_path)}"
    kmd_token = _read_string_path(kmd_token_path)
    kcl = kmd.KMDClient(kmd_token, kmd_url)
    acl = algod.AlgodClient(algod_token, algod_url)