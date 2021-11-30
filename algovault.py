#!/usr/bin/env python3
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
