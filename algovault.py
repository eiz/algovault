#!/usr/bin/env python3
import click

import algovault.client
import algovault.naming
import algovault.subscription


@click.group()
def cli():
    algovault.client.init_environ()


@cli.command()
@click.argument("account")
def do_thing(account):
    acl = algovault.client.get_algod()
    print(acl.account_info(account))


cli.add_command(algovault.naming.command_group)
cli.add_command(algovault.subscription.command_group)

if __name__ == "__main__":
    cli()
