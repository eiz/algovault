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

import os
import os.path

QVOTE_CONTRACTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "third_party",
    "qvote_contracts",
    "contracts",
    "teal",
)
