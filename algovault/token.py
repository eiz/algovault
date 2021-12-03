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
from algosdk.future import transaction
from algovault.client import get_wallet


def create_max_token(
    creator,
    unit_name,
    asset_name,
    manager="",
    reserve="",
    freeze="",
    url="https://str.rs/",
):
    """
    Creates a token with maximum possible supply (uint64 max) and 6
    fractional digits.
    """
    kcl, acl, wallet_handle, pw = get_wallet()
    suggested_params = acl.suggested_params()
    txn = transaction.AssetCreateTxn(
        creator,
        suggested_params,
        0xFFFFFFFFFFFFFFFF,
        6,
        False,
        clawback=creator,
        freeze=freeze,
        manager=manager,
        reserve=reserve,
        unit_name=unit_name,
        asset_name=asset_name,
        url=url,
    )
    signed_txn = kcl.sign_transaction(wallet_handle, pw, txn)
    acl.send_transaction(signed_txn)
    transaction.wait_for_confirmation(acl, signed_txn.get_txid())
