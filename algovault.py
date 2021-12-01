#!/usr/bin/env python3

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

import click

import algovault.client
import algovault.naming
import algovault.subscription


@click.group()
def cli():
    algovault.client.init_environ()


cli.add_command(algovault.naming.command_group)
cli.add_command(algovault.subscription.command_group)

if __name__ == "__main__":
    cli()
