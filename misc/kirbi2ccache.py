import os
import sys
import click
import base64

from minikerberos.common.ccache import CCACHE
from minikerberos.common.kirbi import Kirbi

# cat <file> | grep "doI" | sed 's/ //g'

@click.command()
@click.option('--input', '-i', type=click.File('r'), default=sys.stdin, help='Input base64-encoded tickets')
@click.option('--output', '-o', type=click.Path(), help='File to write CCACHE file')
def main(input, output):
    with input:
        tickets = input.readlines()
    
    cc = CCACHE()
    for ticket in tickets:
        decoded_ticket = base64.b64decode(ticket)
        kirbi = Kirbi.from_bytes(decoded_ticket)
        cc.add_kirbi(kirbi)

    output = os.path.abspath(output)
    cc.to_file(output)
    print('Run `export KRB5CCNAME=FILE:'+output+'`')


if __name__ == '__main__':
    main()