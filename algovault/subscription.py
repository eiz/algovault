import base64
import json

from algosdk.future import template, transaction
from algosdk import encoding, util
from algosdk.kmd import KMDClient
from algosdk.v2client.algod import AlgodClient
import click
from pyteal import *

from algovault.client import get_wallet, raw_signing_address, sha512_256
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
    CODE = base64.b64decode(
        "BSABASYCIENDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDA1N1Yig1AIAgQ"
        "kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI1ASkxF1AtNAEEKTEXUC00AA"
        "QRMSAyAxIQRDEQIhJAACUxEIEGEkAAAQAxGBaACEFBQUFBQUFBEjEZIhIxGYECEhE"
        "QRCJDMQiBABIxCSgSEEQiQw=="
    )

    def __init__(self, app_id, sender, receiver):
        self.app_id = app_id
        self.sender = sender
        self.receiver = receiver

    def get_program(self):
        def replace(arr, new_val, offset, old_len):
            return arr[:offset] + new_val + arr[offset + old_len :]

        code = SubscriptionAccount.CODE
        code = replace(code, encoding.decode_address(self.receiver), 7, 32)
        code = replace(code, encoding.decode_address(self.sender), 48, 32)
        code = replace(code, self.app_id.to_bytes(8, "big"), 127, 8)
        return code


def _subtoken_approval(cash_asset_id, sub_asset_id):
    related_index = ScratchVar(TealType.uint64)
    scratch_subscribe_blob = ScratchVar(TealType.bytes)
    success = Return(Int(1))
    data_key = Bytes("")

    # Subscribe args
    # sub_account
    # receiver
    # amount
    # interval

    arg_payment_sender = Txn.sender()
    arg_sub_account = Txn.application_args[1]
    arg_payment_receiver = Txn.application_args[2]
    arg_amount = Txn.application_args[3]
    arg_interval = Txn.application_args[4]

    on_subscribe = Seq(
        Assert(Len(arg_sub_account) == Int(32)),
        Assert(Len(arg_payment_receiver) == Int(32)),
        Assert(Len(arg_amount) == Int(8)),
        Assert(Len(arg_interval) == Int(8)),
        Assert(App.optedIn(arg_sub_account, Global.current_application_id())),
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
                    Bytes(b"Program" + SubscriptionAccount.CODE[0:7]),
                    Gtxn[related_index.load()].application_args[2],
                    Bytes(SubscriptionAccount.CODE[39:48]),
                    Gtxn[related_index.load()].sender(),
                    Bytes(SubscriptionAccount.CODE[80:127]),
                    Itob(Global.current_application_id()),
                    Bytes(SubscriptionAccount.CODE[135:]),
                )
            )
        ),
        success,
    )

    on_opt_out = Seq(
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields(
            {
                TxnField.type_enum: TxnType.Payment,
                TxnField.receiver: Txn.sender(),
                TxnField.amount: Int(0),
                TxnField.close_remainder_to: Substring(
                    App.localGet(Txn.sender(), data_key), Int(32), Int(64)
                ),
            }
        ),
        InnerTxnBuilder.Submit(),
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
        [Txn.on_completion() == OnComplete.CloseOut, on_opt_out],
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


def _find_free_sub_account(
    kcl: KMDClient,
    acl: AlgodClient,
    wallet_handle: str,
    pw: str,
    sender: str,
    app_id: int,
    max_index: int = 64,
):
    private_key = kcl.export_key(wallet_handle, pw, sender)
    secret = base64.b64decode(
        util.sign_bytes(b"Subscription" + app_id.to_bytes(8, "big"), private_key)
    )

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
            And(Txn.amount() == Int(0), Txn.close_remainder_to() == Bytes(receiver))
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
                Txn.rekey_to() == Global.zero_address(),
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