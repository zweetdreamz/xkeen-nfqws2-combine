#!/usr/bin/env python3
"""Guarded native DNS switch CLI; no changes without --set and --yes-router."""
import argparse
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
from kdn.engine import cli, config, console, dns_mode, lifecycle, options


def main():
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--status',action='store_true')
    group.add_argument('--set',choices=('vless','doh'))
    parser.add_argument('--yes-router',action='store_true')
    args=parser.parse_args()
    parsed=options.parse_args(['--status']+(['--yes-router'] if args.yes_router else []))
    ctx=cli.Context([],os.environ,console.Console(sys.stdout,sys.stderr),paths=config.EnginePaths.from_environ(os.environ),
                    options=parsed,resolved=options.resolve(parsed,''))
    if args.status:
        print(json.dumps(dns_mode.dns_status(ctx),ensure_ascii=False))
        return 0
    lifecycle.install_signal_handlers()
    return dns_mode.switch_dns(ctx,args.set)


if __name__=='__main__':
    raise SystemExit(main())
