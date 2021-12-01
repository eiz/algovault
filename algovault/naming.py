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

# A quick and dirty name service. Probably not secure, has virtually no
# features, but very cheap. The idea here is that we hash the name, embed it
# (and the app ID) into a LogicSig, then rekey that LogicSig account to an
# update authority. There's 0 bullshit: no forced auctions or other
# speculator-bait, just send in the minimum balance for a 16-slot storage and
# away you go.
import base64
import sys

from algosdk import encoding
from algosdk.constants import MIN_TXN_FEE
from algosdk.future import template, transaction
import click
from pyteal import *

from algovault.client import get_algod, get_kmd, raw_signing_address, sha512_256

# testnet app id
DEFAULT_APP_ID = 46576018
# 16 local bytes keys + 100k opt-in balance + 100k base balance
MINIMUM_BALANCE = 16 * 50000 + 100000 + 100000
MINIMUM_TXN_FEE = 1000


def _lsig(program, txn):
    return transaction.LogicSigTransaction(txn, transaction.LogicSigAccount(program))


def _approval_program():
    success = Return(Int(1))
    on_set = Seq(
        [
            App.localPut(
                Txn.sender(), Txn.application_args[1], Txn.application_args[2]
            ),
            Return(Int(1)),
        ]
    )
    on_noop = Cond([Txn.application_args[0] == Bytes("Set"), on_set])
    program = Cond(
        [Txn.application_id() == Int(0), success],
        [Txn.on_completion() == OnComplete.OptIn, success],
        [Txn.on_completion() == OnComplete.CloseOut, success],
        [Txn.on_completion() == OnComplete.NoOp, on_noop],
    )
    return compileTeal(program, Mode.Application, version=5)


def _clear_state_program():
    program = Return(Int(1))
    return compileTeal(program, Mode.Application, version=5)


class NamedAccount(template.Template):
    def __init__(self, name_service_id, name):
        self.name_service_id = name_service_id
        if isinstance(name, str):
            name = name.encode("utf-8")
        self.name = name

    def get_program(self):
        program = bytearray()
        # version
        template.put_uvarint(program, 5)
        program.append(0x80)  # pushbytes
        template.put_uvarint(program, 32)
        program.extend(sha512_256(self.name))
        program.append(0x81)  # pushint
        template.put_uvarint(program, self.name_service_id)
        # pop; pop; pushint 1
        program.extend([0x48, 0x48, 0x81, 0x01])
        return bytes(program)

    def initialize(self, sp, funding_address, update_authority):
        acl = get_algod()
        program = self.get_program()
        addr = self.get_address()
        fund_txn = transaction.PaymentTxn(
            funding_address, sp, addr, MINIMUM_BALANCE + MIN_TXN_FEE
        )
        optin_txn = transaction.ApplicationOptInTxn(
            addr, sp, DEFAULT_APP_ID, rekey_to=update_authority
        )
        group = [fund_txn, optin_txn]
        transaction.assign_group_id(group)
        return (fund_txn, _lsig(program, optin_txn))

    def update_data(self, sp, data_index, data):
        return transaction.ApplicationCallTxn(
            self.get_address(),
            sp,
            DEFAULT_APP_ID,
            transaction.OnComplete.NoOpOC.real,
            app_args=[b"Set", data_index, data],
        )

    def close(self, sp, remainder_to):
        close_out = transaction.ApplicationCloseOutTxn(
            self.get_address(), sp, DEFAULT_APP_ID
        )
        payback = transaction.PaymentTxn(
            self.get_address(),
            sp,
            self.get_address(),
            0,
            close_remainder_to=remainder_to,
        )
        transaction.assign_group_id([close_out, payback])
        return close_out, payback


@click.group("name")
def command_group():
    pass


@command_group.command("deploy")
def name_deploy():
    kcl = get_kmd()
    acl = get_algod()
    wallets = kcl.list_wallets()
    wallet_handle = kcl.init_wallet_handle(wallets[0]["id"], "")
    creator = kcl.list_keys(wallet_handle)[0]
    approval_bytecode = acl.compile(_approval_program())
    clear_state_bytecode = acl.compile(_clear_state_program())
    suggested_params = acl.suggested_params()
    global_schema = transaction.StateSchema(0, 0)
    local_schema = transaction.StateSchema(0, 16)
    txn = transaction.ApplicationCreateTxn(
        creator,
        suggested_params,
        transaction.OnComplete.NoOpOC.real,
        base64.b64decode(approval_bytecode["result"]),
        base64.b64decode(clear_state_bytecode["result"]),
        global_schema,
        local_schema,
    )
    signed_txn = kcl.sign_transaction(wallet_handle, "", txn)
    acl.send_transaction(signed_txn)
    transaction.wait_for_confirmation(acl, signed_txn.get_txid(), 5)
    transaction_response = acl.pending_transaction_info(signed_txn.get_txid())
    app_id = transaction_response["application-index"]
    print("Created new app-id:", app_id)


@command_group.command("create")
@click.argument("name")
@click.argument("authority")
def name_create(name, authority):
    acl = get_algod()
    kcl = get_kmd()
    acct = NamedAccount(DEFAULT_APP_ID, name)
    suggested_params = acl.suggested_params()
    wallets = kcl.list_wallets()
    wallet_handle = kcl.init_wallet_handle(wallets[0]["id"], "")
    fund, optin = acct.initialize(suggested_params, authority, authority)
    signed_fund = kcl.sign_transaction(wallet_handle, "", fund)
    group_txid = acl.send_transactions([signed_fund, optin])
    transaction.wait_for_confirmation(acl, group_txid, 5)
    pass


@command_group.command("delete")
@click.argument("signer")
@click.argument("receiver")
@click.argument("name")
def name_delete(signer, receiver, name):
    acl = get_algod()
    kcl = get_kmd()
    acct = NamedAccount(DEFAULT_APP_ID, name)
    suggested_params = acl.suggested_params()
    wallets = kcl.list_wallets()
    wallet_handle = kcl.init_wallet_handle(wallets[0]["id"], "")
    close_out, payback = acct.close(suggested_params, receiver)
    signed_close_out = kcl.sign_transaction(
        wallet_handle, "", close_out, signing_address=raw_signing_address(signer)
    )
    signed_payback = kcl.sign_transaction(
        wallet_handle, "", payback, signing_address=raw_signing_address(signer)
    )
    txid = acl.send_transactions([signed_close_out, signed_payback])
    transaction.wait_for_confirmation(acl, txid, 5)


@command_group.command("update")
@click.argument("signer")
@click.argument("name")
@click.argument("index")
@click.argument("data")
def name_update(signer, name, index, data):
    acl = get_algod()
    kcl = get_kmd()
    acct = NamedAccount(DEFAULT_APP_ID, name)
    suggested_params = acl.suggested_params()
    wallets = kcl.list_wallets()
    wallet_handle = kcl.init_wallet_handle(wallets[0]["id"], "")
    txn = acct.update_data(
        suggested_params, index.encode("utf-8"), data.encode("utf-8")
    )
    signed_txn = kcl.sign_transaction(
        wallet_handle,
        "",
        txn,
        signing_address=raw_signing_address(signer),
    )
    acl.send_transaction(signed_txn)
    transaction.wait_for_confirmation(acl, signed_txn.get_txid(), 5)


@command_group.command("get")
@click.argument("name")
@click.argument("index")
def name_get(name, index):
    acl = get_algod()
    acct = NamedAccount(DEFAULT_APP_ID, name)
    info = acl.account_info(acct.get_address())
    b64_index = base64.b64encode(index.encode("utf-8")).decode("utf-8")
    for app_state in info["apps-local-state"]:
        if app_state["id"] == DEFAULT_APP_ID:
            if "key-value" in app_state:
                for key_value in app_state["key-value"]:
                    if key_value["key"] == b64_index:
                        print(
                            base64.b64decode(key_value["value"]["bytes"]).decode(
                                "utf-8"
                            )
                        )
                        return
    click.echo("couldn't find a value for the given key", err=True)
    sys.exit(1)
