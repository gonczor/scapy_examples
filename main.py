#! /usr/bin/env python3

import argparse
import sys

from commands.discover_ports import main as dp_main
from commands.traceroute import main as tr_main
from commands.sniff import main as sniff_main
from commands.fuzzer import main as fuzz_main


COMMAND_MAPPING = {
    'discover_ports': dp_main,
    'traceroute': tr_main,
    'sniff': sniff_main,
    'fuzz': fuzz_main,
}


def add_parser() -> argparse.ArgumentParser:
    _parser = argparse.ArgumentParser(description='Parse options')
    _parser.add_argument(
        'command',
        type=str,
        help='specify command to run. Options are: '
             '\n\t- discover_ports - open scan ports 0-1000'
             '\n\t- traceroute - trace route to host'
             '\n\t- sniff - sniff packets'
             '\n\t- fuzz - fuzz an interface'
    )
    _parser.add_argument(
        'host',
        type=str,
        help='IP v4 address of host.'
    )
    _parser.add_argument(
        '-i',
        help='Interface to sniff (only for sniff command)',
        default=None,
        nargs='?'
    )
    _parser.add_argument(
        '-p',
        help='Port to fuzz (only for fuzz command)',
        default=80,
        type=int,
        nargs='?'
    )

    return _parser


if __name__ == '__main__':
    parser = add_parser()
    args = parser.parse_args()
    try:
        COMMAND_MAPPING.get(args.command, None)(args.host, args.i or args.p)
    except TypeError as e:
        valid_options = '\n\t- '.join(command for command in COMMAND_MAPPING.keys())
        print(f'Command {args.command} has not been recognized. '
              f'Valid options are:\n\t- {valid_options}.')
        sys.exit(1)
