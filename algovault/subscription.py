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

# ... There was an attempt. This isn't really tested and probably has vulns.
#
# In principle: a simple subscription payments service which offers some nice
# features for the end user. The most obvious ways of doing subscription
# payments on Algorand are not really attractive as a merchant for a few
# reasons:
#
# 1. You can use escrow accounts, as provided by the PeriodicPayment template in
#    the SDK. There's a number of problems with this. Each subscription requires
#    its own escrow account, which will have a separate balance from your main
#    account (not good wallet UX), there is no on-chain record of who is being
#    paid by whom except by groveling through transaction logs, they are not
#    easy to cancel, they make an assumption about block time that's not a
#    guaranteed part of the protocol, etc.
#
# 2. You can create wallet software with bill-pay type functionality. This can
#    be made to work reasonably well, but as a merchant I do not want to rely on
#    the user running specific client software in order for me to get paid. Have
#    to add the feature to N different wallet programs.
#
# This module attempts to implement a somewhat streamlined version of #1.
# Instead of using accounts as an escrow, we use a token which can be atomically
# swapped for an underlying asset. This token has a clawback contract which
# allows a designated receiver to periodically withdraw funds from the sender
# address. Some advantages:
#
# 1. Either the sender or receiver can cancel the contract at any time.
# 2. Subscriptions are easily enumerable by the sender using only current (non
#    archival) on-chain metadata. The way this works is by building
#    NamedAccounts using a secret only the wallet owner knows, plus a sequence
#    number. The NamedAccount is then rekeyed to a LogicSig which implements the
#    cancellation logic. An unlimited number of subscriptions are supported by
#    storing the payment state inside local storage on the per-subscription
#    account, which never contains any funds other than minimum balances.
#
#    Enumerability means that a dapp or wallet can provide a management UI that
#    shows all of your subscriptions, their payment dates, your spend over time,
#    and so on, which is a much nicer experience than what you get subscribing
#    to things with a credit card.
# 3. If you have many subscriptions, you don't need to fund escrow accounts
#    separately for each one. Accounts do exist for each subscription, but they
#    never hold the actual funds.
# 4. Receiver pays most fees, including the minimum balance for the sub account.
#
# The downside is, well, it's still not fully automatic. But you can just grab a
# bag of these tokens and they're as good as cash for anyone who receives them.
#
# TODO
# - Test suite
# - Move off of NamedAccounts to something with a stronger sig. The current
#   implementation is technically susceptible to front-running DoS attacks. The
#   thing about NamedAccounts is they need to be globally discoverable without
#   knowing the owner, but we don't care about that here.
# - Implement staking of native ALGOs instead of just ASAs. I might want to keep
#   the implementation of that separate from this though, so rewards can be
#   properly distributed. I think there's already some tokenizations like wALGO
#   that people can use, anyway?
# - TypeScript implementation for web use
# - Dispense job / sub tracking service for merchant side
# - TEAL date math primitives so true monthly etc payments can be implemented
#   instead of just frictionless spherical 4 week months ;)
import base64
import json
import sys

from algosdk.future import template, transaction
from algosdk import encoding, logic, util
from algosdk.kmd import KMDClient
from algosdk.v2client.algod import AlgodClient
import click
from pyteal import *

from algovault.client import get_wallet
from algovault.naming import NamedAccount

DEBUG_MODE = True

# TestNet
DEFAULT_APP_ID = 48056122
DEFAULT_CASH_ID = 47862693
DEFAULT_SUB_ID = 47855407


def _encode_app_address(app_id):
    return encoding.encode_address(
        encoding.checksum(b"appID" + app_id.to_bytes(8, "big"))
    )


class SubscriptionAccount(template.Template):
    # See gen_template for the source code to this signature program.
    CODE = base64.b64decode(
        "BSACAQAmAiBDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQwNTdWIoNQCAI"
        "EJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCNQEpMRdQLTQBBCkxF1AtNA"
        "AEETEgMgMSEDEBIxIQRDEQIhJAACUxEIEGEkAAAQAxGBaACEFBQUFBQUFBEjEZIhI"
        "xGYECEhEQRCJDMQgjEjEJKBIQRCJD"
    )

    def __init__(self, app_id, sender, receiver):
        self.app_id = app_id
        self.sender = sender
        self.receiver = receiver

    def get_program(self):
        def replace(arr, new_val, offset, old_len):
            return arr[:offset] + new_val + arr[offset + old_len :]

        code = SubscriptionAccount.CODE
        code = replace(code, encoding.decode_address(self.receiver), 8, 32)
        code = replace(code, encoding.decode_address(self.sender), 49, 32)
        code = replace(code, self.app_id.to_bytes(8, "big"), 133, 8)
        return code


def _subtoken_approval(cash_asset_id, sub_asset_id):
    related_index = ScratchVar(TealType.uint64)
    scratch_subscribe_blob = ScratchVar(TealType.bytes)
    success = Return(Int(1))
    data_key = Bytes("")
    # Aliases for subscribe call arguments.
    arg_payment_sender = Txn.sender()
    arg_sub_account = Txn.application_args[1]
    arg_payment_receiver = Txn.application_args[2]
    arg_amount = Txn.application_args[3]
    arg_interval = Txn.application_args[4]
    on_subscribe = Seq(
        # Check arg lengths
        Assert(Len(arg_sub_account) == Int(32)),
        Assert(Len(arg_payment_receiver) == Int(32)),
        Assert(Len(arg_amount) == Int(8)),
        Assert(Len(arg_interval) == Int(8)),
        Assert(App.optedIn(arg_sub_account, Global.current_application_id())),
        # Must not already be a subscription
        Assert(App.localGet(arg_sub_account, data_key) == Int(0)),
        App.localPut(
            arg_sub_account,
            data_key,
            Concat(
                # 0
                arg_payment_sender,
                # 32
                arg_payment_receiver,
                # 64
                arg_amount,
                # 72
                arg_interval,
                # 80
                Itob(Global.latest_timestamp() + Btoi(arg_interval)),
            ),
        ),
        success,
    )
    on_dispense = Seq(
        scratch_subscribe_blob.store(App.localGet(arg_sub_account, data_key)),
        Assert(
            Txn.sender() == Substring(scratch_subscribe_blob.load(), Int(32), Int(64))
        ),
        Assert(
            Global.latest_timestamp()
            >= Btoi(Substring(scratch_subscribe_blob.load(), Int(80), Int(88)))
        ),
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields(
            {
                TxnField.type_enum: TxnType.AssetTransfer,
                TxnField.asset_sender: Substring(
                    scratch_subscribe_blob.load(), Int(0), Int(32)
                ),
                TxnField.asset_receiver: Substring(
                    scratch_subscribe_blob.load(), Int(32), Int(64)
                ),
                TxnField.asset_amount: Btoi(
                    Substring(scratch_subscribe_blob.load(), Int(64), Int(72))
                ),
                TxnField.xfer_asset: Int(sub_asset_id),
            }
        ),
        InnerTxnBuilder.Submit(),
        App.localPut(
            arg_sub_account,
            data_key,
            Concat(
                Substring(scratch_subscribe_blob.load(), Int(0), Int(80)),
                Itob(
                    Btoi(Substring(scratch_subscribe_blob.load(), Int(80), Int(88)))
                    + Btoi(Substring(scratch_subscribe_blob.load(), Int(72), Int(80)))
                ),
            ),
        ),
        success,
    )
    on_opt_in = Seq(
        # Subscribe transaction must follow opt-in in the group
        Assert(Txn.group_index() + Int(1) < Global.group_size()),
        related_index.store(Txn.group_index() + Int(1)),
        Assert(Gtxn[related_index.load()].type_enum() == TxnType.ApplicationCall),
        Assert(Gtxn[related_index.load()].on_completion() == OnComplete.NoOp),
        Assert(Gtxn[related_index.load()].application_args[0] == Bytes(b"Subscribe")),
        # And must be sent to the same app
        Assert(
            Gtxn[related_index.load()].application_id()
            == Global.current_application_id()
        ),
        # And must be subscribing this sub account
        Assert(Gtxn[related_index.load()].application_args[1] == Txn.sender()),
        # And must rekey to the sub control LogicSig to allow cancellation
        Assert(
            Txn.rekey_to()
            == Sha512_256(
                Concat(
                    Bytes(b"Program" + SubscriptionAccount.CODE[0:8]),
                    Gtxn[related_index.load()].application_args[2],
                    Bytes(SubscriptionAccount.CODE[40:49]),
                    Gtxn[related_index.load()].sender(),
                    Bytes(SubscriptionAccount.CODE[81:133]),
                    Itob(Global.current_application_id()),
                    Bytes(SubscriptionAccount.CODE[141:]),
                )
            )
        ),
        success,
    )
    on_initialize = Seq(
        Assert(Txn.sender() == Global.creator_address()),
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields(
            {
                TxnField.type_enum: TxnType.AssetTransfer,
                TxnField.asset_receiver: Global.current_application_address(),
                TxnField.asset_amount: Int(0),
                TxnField.xfer_asset: Int(sub_asset_id),
            }
        ),
        InnerTxnBuilder.Submit(),
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields(
            {
                TxnField.type_enum: TxnType.AssetTransfer,
                TxnField.asset_receiver: Global.current_application_address(),
                TxnField.asset_amount: Int(0),
                TxnField.xfer_asset: Int(cash_asset_id),
            }
        ),
        InnerTxnBuilder.Submit(),
        success,
    )

    def _token_swap(receive_asset, send_asset):
        return Seq(
            Assert(Txn.group_index() > Int(0)),
            related_index.store(Txn.group_index() - Int(1)),
            Assert(
                And(
                    Gtxn[related_index.load()].type_enum() == TxnType.AssetTransfer,
                    Gtxn[related_index.load()].asset_receiver()
                    == Global.current_application_address(),
                    Gtxn[related_index.load()].xfer_asset() == Int(receive_asset),
                )
            ),
            InnerTxnBuilder.Begin(),
            InnerTxnBuilder.SetFields(
                {
                    TxnField.type_enum: TxnType.AssetTransfer,
                    TxnField.asset_amount: Gtxn[related_index.load()].asset_amount(),
                    TxnField.asset_receiver: Txn.application_args[1],
                    TxnField.xfer_asset: Int(send_asset),
                }
            ),
            InnerTxnBuilder.Submit(),
            success,
        )

    on_cash_in = _token_swap(cash_asset_id, sub_asset_id)
    on_cash_out = _token_swap(sub_asset_id, cash_asset_id)
    on_noop = Cond(
        [Txn.application_args[0] == Bytes("Initialize"), on_initialize],
        [Txn.application_args[0] == Bytes("CashIn"), on_cash_in],
        [Txn.application_args[0] == Bytes("CashOut"), on_cash_out],
        [Txn.application_args[0] == Bytes("Subscribe"), on_subscribe],
        [Txn.application_args[0] == Bytes("Dispense"), on_dispense],
    )
    debug_conds = []
    if DEBUG_MODE:
        on_update_app = Seq(Assert(Txn.sender() == Global.creator_address()), success)
        debug_conds = [
            [Txn.on_completion() == OnComplete.UpdateApplication, on_update_app],
            [Txn.on_completion() == OnComplete.DeleteApplication, on_update_app],
        ]
    program = Cond(
        [Txn.application_id() == Int(0), success],
        [Txn.on_completion() == OnComplete.OptIn, on_opt_in],
        # Close-out is always allowed. Sub account logicsig controls approval
        # and disbursement of remaining balance.
        [Txn.on_completion() == OnComplete.CloseOut, success],
        [Txn.on_completion() == OnComplete.NoOp, on_noop],
        *debug_conds
    )
    return compileTeal(program, Mode.Application, version=5)


def _clear_state_program():
    program = Return(Int(1))
    return compileTeal(program, Mode.Application, version=5)


@click.group("subscription")
def command_group():
    pass


@command_group.command()
@click.option("--cash_asset_id", type=click.INT, required=True, default=DEFAULT_CASH_ID)
@click.option("--sub_asset_id", type=click.INT, required=True, default=DEFAULT_SUB_ID)
def teal(cash_asset_id, sub_asset_id):
    print(_subtoken_approval(cash_asset_id, sub_asset_id))


@command_group.command()
@click.option("--creator", required=True)
@click.option("--cash_asset_id", type=click.INT, required=True, default=DEFAULT_CASH_ID)
@click.option("--sub_asset_id", type=click.INT, required=True, default=DEFAULT_SUB_ID)
def deploy(creator, cash_asset_id, sub_asset_id):
    kcl, acl, wallet_handle, pw = get_wallet()
    approval_bytecode = acl.compile(_subtoken_approval(cash_asset_id, sub_asset_id))
    clear_state_bytecode = acl.compile(_clear_state_program())
    suggested_params = acl.suggested_params()
    global_schema = transaction.StateSchema(0, 0)
    local_schema = transaction.StateSchema(0, 1)
    txn = transaction.ApplicationCreateTxn(
        creator,
        suggested_params,
        transaction.OnComplete.NoOpOC.real,
        base64.b64decode(approval_bytecode["result"]),
        base64.b64decode(clear_state_bytecode["result"]),
        global_schema,
        local_schema,
    )
    signed_txn = kcl.sign_transaction(wallet_handle, pw, txn)
    acl.send_transaction(signed_txn)
    transaction.wait_for_confirmation(acl, signed_txn.get_txid(), 5)
    transaction_response = acl.pending_transaction_info(signed_txn.get_txid())
    app_id = transaction_response["application-index"]
    print("Created new app-id:", app_id, "account:", _encode_app_address(app_id))


@command_group.command()
@click.option("--creator", required=True)
@click.option("--cash_asset_id", type=click.INT, required=True, default=DEFAULT_CASH_ID)
@click.option("--sub_asset_id", type=click.INT, required=True, default=DEFAULT_SUB_ID)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
def update(creator, cash_asset_id, sub_asset_id, app_id):
    kcl, acl, wallet_handle, pw = get_wallet()
    approval_bytecode = acl.compile(_subtoken_approval(cash_asset_id, sub_asset_id))
    clear_state_bytecode = acl.compile(_clear_state_program())
    suggested_params = acl.suggested_params()
    txn = transaction.ApplicationUpdateTxn(
        creator,
        suggested_params,
        app_id,
        base64.b64decode(approval_bytecode["result"]),
        base64.b64decode(clear_state_bytecode["result"]),
    )
    signed_txn = kcl.sign_transaction(wallet_handle, pw, txn)
    acl.send_transaction(signed_txn)
    transaction.wait_for_confirmation(acl, signed_txn.get_txid(), 5)


@command_group.command()
@click.option("--creator", required=True)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
@click.option("--cash_asset_id", type=click.INT, required=True, default=DEFAULT_CASH_ID)
@click.option("--sub_asset_id", type=click.INT, required=True, default=DEFAULT_SUB_ID)
def initialize(creator, app_id, cash_asset_id, sub_asset_id):
    app_address = _encode_app_address(app_id)
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    fund_txn = transaction.PaymentTxn(creator, suggested_params, app_address, 302000)
    init_txn = transaction.ApplicationCallTxn(
        creator,
        suggested_params,
        app_id,
        transaction.OnComplete.NoOpOC.real,
        app_args=[b"Initialize"],
        foreign_assets=[cash_asset_id, sub_asset_id],
    )
    group = [fund_txn, init_txn]
    transaction.assign_group_id(group)
    group = [kcl.sign_transaction(wallet_handle, pw, tx) for tx in group]
    group_txid = acl.send_transactions(group)
    transaction.wait_for_confirmation(acl, group_txid, 5)


@command_group.command()
@click.option("--creator", required=True)
@click.option("--sub_asset_id", type=click.INT, required=True)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
def attach(creator, sub_asset_id, app_id):
    app_address = _encode_app_address(app_id)
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    txn = transaction.AssetUpdateTxn(
        creator,
        suggested_params,
        sub_asset_id,
        manager=creator,
        reserve=app_address,
        clawback=app_address,
        freeze="",
    )
    signed_txn = kcl.sign_transaction(wallet_handle, pw, txn)
    acl.send_transaction(signed_txn)
    transaction.wait_for_confirmation(acl, signed_txn.get_txid(), 5)


def _atomic_swap(op, sender, amount, input_asset_id, output_asset_id, app_id):
    app_address = _encode_app_address(app_id)
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    fee_txn = transaction.PaymentTxn(sender, suggested_params, app_address, 1000)
    fund_txn = transaction.AssetTransferTxn(
        sender, suggested_params, app_address, amount, input_asset_id
    )
    recv_txn = transaction.ApplicationCallTxn(
        sender,
        suggested_params,
        app_id,
        transaction.OnComplete.NoOpOC.real,
        app_args=[op, encoding.decode_address(sender)],
        foreign_assets=[input_asset_id, output_asset_id],
    )
    group = [fee_txn, fund_txn, recv_txn]
    transaction.assign_group_id(group)
    signed_group = [kcl.sign_transaction(wallet_handle, pw, txn) for txn in group]
    group_txid = acl.send_transactions(signed_group)
    transaction.wait_for_confirmation(acl, group_txid, 5)


@command_group.command()
@click.option("--sender", required=True)
@click.option("--amount", type=click.INT, required=True)
@click.option("--cash_asset_id", type=click.INT, required=True, default=DEFAULT_CASH_ID)
@click.option("--sub_asset_id", type=click.INT, required=True, default=DEFAULT_SUB_ID)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
def cash_in(sender, amount, cash_asset_id, sub_asset_id, app_id):
    _atomic_swap(b"CashIn", sender, amount, cash_asset_id, sub_asset_id, app_id)


@command_group.command()
@click.option("--sender", required=True)
@click.option("--amount", type=click.INT, required=True)
@click.option("--cash_asset_id", type=click.INT, required=True, default=DEFAULT_CASH_ID)
@click.option("--sub_asset_id", type=click.INT, required=True, default=DEFAULT_SUB_ID)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
def cash_out(sender, amount, cash_asset_id, sub_asset_id, app_id):
    _atomic_swap(b"CashOut", sender, amount, sub_asset_id, cash_asset_id, app_id)


def _get_sub_account_secret(kcl, wallet_handle, pw, sender, app_id):
    private_key = kcl.export_key(wallet_handle, pw, sender)
    secret = base64.b64decode(
        util.sign_bytes(b"Subscription" + app_id.to_bytes(8, "big"), private_key)
    )
    return secret


def _get_sub_account_data(info, app_id):
    for app_state in info["apps-local-state"]:
        if app_state["id"] == app_id:
            for kv in app_state["key-value"]:
                if kv["key"] == "":
                    data = base64.b64decode(kv["value"]["bytes"])
                    return {
                        "sender": encoding.encode_address(data[0:32]),
                        "receiver": encoding.encode_address(data[32:64]),
                        "amount": int.from_bytes(data[64:72], "big"),
                        "interval": int.from_bytes(data[72:80], "big"),
                        "next": int.from_bytes(data[80:88], "big"),
                    }
    return None


def _find_free_sub_account(
    kcl: KMDClient,
    acl: AlgodClient,
    wallet_handle: str,
    pw: str,
    sender: str,
    app_id: int,
    max_index: int = 64,
):
    secret = _get_sub_account_secret(kcl, wallet_handle, pw, sender, app_id)
    for i in range(max_index):
        account = NamedAccount(app_id, secret + i.to_bytes(8, "big"))
        address = account.get_address()
        info = acl.account_info(address)
        if info["amount"] == 0:
            return account, i
    raise Exception("Couldn't find a free subscription slot to use.")


@command_group.command()
@click.option("--sender", required=True)
@click.option("--receiver", required=True)
@click.option("--amount", type=click.INT, required=True)
@click.option("--interval", type=click.INT, required=True)
@click.option("--sub_asset_id", type=click.INT, required=True, default=DEFAULT_SUB_ID)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
@click.option("--out_file", type=click.Path(), required=True)
@click.option("--sign_sender/--no_sign_sender", default=False)
@click.option("--sign_receiver/--no_sign_receiver", default=False)
def request(
    sender,
    receiver,
    amount,
    interval,
    sub_asset_id,
    app_id,
    out_file,
    sign_sender,
    sign_receiver,
):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    # TODO(eiz): This is kind of brutal. The sender and receiver need to agree
    # on a valid round range, but since we're just regenerating the transactions
    # on both sides to confirm that they agree, they won't unless the last block
    # is the exact same. Round down to the previous multiple of 200 for the
    # minimum. This can break and need to be retried if you happen to cross over
    # between generating the sender and receiver txs.
    #
    # Proper fix is to explicitly tell the sender/receiver the valid block range
    # to use, but I'm keeping it this way for CLI purposes for now.
    suggested_params.first = suggested_params.first // 200 * 200
    suggested_params.last = suggested_params.first + 1000
    sub_account, _ = _find_free_sub_account(kcl, acl, wallet_handle, pw, sender, app_id)
    sub_address = sub_account.get_address()
    sig_account = SubscriptionAccount(app_id, sender, receiver)
    fund_txn = transaction.PaymentTxn(receiver, suggested_params, sub_address, 251000)
    optin_txn = transaction.ApplicationOptInTxn(
        sub_address, suggested_params, app_id, rekey_to=sig_account.get_address()
    )
    sub_txn = transaction.ApplicationCallTxn(
        sender,
        suggested_params,
        app_id,
        transaction.OnComplete.NoOpOC,
        app_args=[
            b"Subscribe",
            encoding.decode_address(sub_address),
            encoding.decode_address(receiver),
            amount.to_bytes(8, "big"),
            interval.to_bytes(8, "big"),
        ],
        accounts=[sub_address],
    )
    initial_payment_txn = transaction.AssetTransferTxn(
        sender,
        suggested_params,
        receiver,
        amount,
        sub_asset_id,
    )
    group = [fund_txn, optin_txn, sub_txn, initial_payment_txn]
    transaction.assign_group_id(group)
    output = {}
    if sign_sender:
        output["optin"] = encoding.msgpack_encode(
            transaction.LogicSigTransaction(
                optin_txn, transaction.LogicSigAccount(sub_account.get_program())
            )
        )
        output["sub"] = encoding.msgpack_encode(
            kcl.sign_transaction(wallet_handle, pw, sub_txn)
        )
        output["initial_payment"] = encoding.msgpack_encode(
            kcl.sign_transaction(wallet_handle, pw, initial_payment_txn)
        )
    if sign_receiver:
        output["fund"] = encoding.msgpack_encode(
            kcl.sign_transaction(wallet_handle, pw, fund_txn)
        )
    with open(out_file, "w") as f:
        json.dump(output, f)


@command_group.command()
@click.option("--receiver_file", type=click.Path(), required=True)
@click.option("--sender_file", type=click.Path(), required=True)
def submit(sender_file, receiver_file):
    _, acl, _, _ = get_wallet()
    with open(sender_file, "r") as f:
        sender_json = json.load(f)
    with open(receiver_file, "r") as f:
        receiver_json = json.load(f)
    group = [
        encoding.future_msgpack_decode(receiver_json["fund"]),
        encoding.future_msgpack_decode(sender_json["optin"]),
        encoding.future_msgpack_decode(sender_json["sub"]),
        encoding.future_msgpack_decode(sender_json["initial_payment"]),
    ]
    group_txid = acl.send_transactions(group)
    transaction.wait_for_confirmation(acl, group_txid, 5)


@command_group.command("list")
@click.option("--sender", required=True)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
@click.option("--max_index", type=click.INT, required=True, default=64)
def list_cmd(sender, app_id, max_index):
    kcl, acl, wallet_handle, pw = get_wallet()
    secret = _get_sub_account_secret(kcl, wallet_handle, pw, sender, app_id)
    for i in range(max_index):
        account = NamedAccount(app_id, secret + i.to_bytes(8, "big"))
        info = acl.account_info(account.get_address())
        sub_data = _get_sub_account_data(info, app_id)
        if sub_data is not None:
            print("Account:", account.get_address(), sub_data)


@command_group.command()
@click.option("--signer", required=True)
@click.option("--sub_address", required=True)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
def close(signer, sub_address, app_id):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    sub_data = _get_sub_account_data(acl.account_info(sub_address), app_id)
    sub_account = SubscriptionAccount(app_id, sub_data["sender"], sub_data["receiver"])
    if sub_data is None:
        click.echo("Couldn't find a subscription at the given address", err=True)
        sys.exit(1)
    fee_txn = transaction.PaymentTxn(signer, suggested_params, sub_address, 0)
    optout_txn = transaction.ApplicationCloseOutTxn(
        sub_address, suggested_params, app_id
    )
    close_txn = transaction.PaymentTxn(
        sub_address,
        suggested_params,
        sub_data["receiver"],
        0,
        close_remainder_to=sub_data["receiver"],
    )
    fee_txn.fee += optout_txn.fee
    fee_txn.fee += close_txn.fee
    optout_txn.fee = 0
    close_txn.fee = 0
    group = [fee_txn, optout_txn, close_txn]
    transaction.assign_group_id(group)
    program = sub_account.get_program()
    private_key = kcl.export_key(wallet_handle, pw, signer)
    group = [
        transaction.LogicSigTransaction(
            tx,
            transaction.LogicSigAccount(
                program,
                [
                    logic.teal_sign_from_program(
                        private_key,
                        b"Sub"
                        + base64.b32decode(encoding._correct_padding(tx.get_txid())),
                        program,
                    )
                ],
            ),
        )
        if tx.sender == sub_address
        else kcl.sign_transaction(wallet_handle, pw, tx)
        for tx in group
    ]
    group_txid = acl.send_transactions(group)
    transaction.wait_for_confirmation(acl, group_txid, 5)


@command_group.command()
@click.option("--sub_address", required=True)
@click.option("--sub_asset_id", type=click.INT, required=True, default=DEFAULT_SUB_ID)
@click.option("--app_id", type=click.INT, required=True, default=DEFAULT_APP_ID)
def dispense(sub_address, sub_asset_id, app_id):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    sub_data = _get_sub_account_data(acl.account_info(sub_address), app_id)
    app_address = _encode_app_address(app_id)
    if not sub_data:
        click.echo("Could not find sub information at the given address.", err=True)
        sys.exit(1)
    fund_txn = transaction.PaymentTxn(
        sub_data["receiver"], suggested_params, app_address, suggested_params.min_fee
    )
    txn = transaction.ApplicationCallTxn(
        sub_data["receiver"],
        suggested_params,
        app_id,
        transaction.OnComplete.NoOpOC.real,
        app_args=[b"Dispense", encoding.decode_address(sub_address)],
        accounts=[sub_address, sub_data["sender"]],
        foreign_assets=[sub_asset_id],
    )
    group = [fund_txn, txn]
    transaction.assign_group_id(group)
    group = [kcl.sign_transaction(wallet_handle, pw, tx) for tx in group]
    group_txid = acl.send_transactions(group)
    transaction.wait_for_confirmation(acl, group_txid, 5)


@command_group.command()
@click.option("--creator", required=True)
@click.option("--reserve", required=True)
def create_token(creator, reserve):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    txn = transaction.AssetCreateTxn(
        creator,
        suggested_params,
        0xFFFFFFFFFFFFFFFF,
        6,
        False,
        clawback=creator,
        manager=creator,
        reserve=reserve,
        unit_name="SUB",
        asset_name="Subscription Token",
        url="https://str.rs/subtoken",
    )
    signed_txn = kcl.sign_transaction(wallet_handle, pw, txn)
    acl.send_transaction(signed_txn)
    transaction.wait_for_confirmation(acl, signed_txn.get_txid(), 5)


@command_group.command()
@click.option("--creator", required=True)
@click.option("--reserve", required=True)
def create_fake_token(creator, reserve):
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    txn = transaction.AssetCreateTxn(
        creator,
        suggested_params,
        0xFFFFFFFFFFFFFFFF,
        6,
        False,
        clawback=creator,
        manager=creator,
        reserve=reserve,
        unit_name="FUSD",
        asset_name="Fake USD",
        url="https://str.rs/subtoken",
    )
    signed_txn = kcl.sign_transaction(wallet_handle, pw, txn)
    acl.send_transaction(signed_txn)
    transaction.wait_for_confirmation(acl, signed_txn.get_txid(), 5)


@command_group.command()
def gen_template():
    _, acl, _, _ = get_wallet()
    app_id = b"A" * 8
    sender = b"B" * 32
    receiver = b"C" * 32
    store_receiver = ScratchVar(TealType.bytes)
    store_sender = ScratchVar(TealType.bytes)
    sig_blob = Concat(Bytes("Sub"), Txn.tx_id())
    verify_payment = Seq(
        Assert(
            And(
                # Must be a close-out transaction
                Txn.amount() == Int(0),
                # Receiver always pays for the sub account, so receiver always gets the refund.
                Txn.close_remainder_to() == Bytes(receiver),
            )
        ),
        Approve(),
    )
    verify_app_call = Seq(
        Assert(
            And(
                Itob(Txn.application_id()) == Bytes(app_id),
                Or(
                    Txn.on_completion() == OnComplete.OptIn,
                    Txn.on_completion() == OnComplete.CloseOut,
                ),
            )
        ),
        Approve(),
    )
    program = Seq(
        store_receiver.store(Bytes(receiver)),
        store_sender.store(Bytes(sender)),
        Assert(
            And(
                Or(
                    Ed25519Verify(sig_blob, Arg(0), store_sender.load()),
                    Ed25519Verify(sig_blob, Arg(0), store_receiver.load()),
                ),
                # Don't allow further rekeys
                Txn.rekey_to() == Global.zero_address(),
                # Ensure that the initiator of the cancellation pays the fee
                # (via fee pooling)
                Txn.fee() == Int(0),
            )
        ),
        Cond(
            [Txn.type_enum() == TxnType.Payment, verify_payment],
            [Txn.type_enum() == TxnType.ApplicationCall, verify_app_call],
        ),
    )
    asm = compileTeal(program, Mode.Signature, version=5)
    bytecode = acl.compile(asm)["result"]
    raw_bytecode = base64.b64decode(bytecode)
    print(
        json.dumps(
            {
                "program": bytecode,
                "app_id": raw_bytecode.find(app_id),
                "sender": raw_bytecode.find(sender),
                "receiver": raw_bytecode.find(receiver),
            }
        )
    )
