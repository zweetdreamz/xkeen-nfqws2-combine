"""Render every composed profile, including empty profiles and global options."""

import os

from kdn.engine import compose, config


def render(composition):
    result, tokens = [], []
    number = 1
    for token in composition.tokens:
        if token == '--new':
            result.append(f'PROFILE|{number}|{"user" if number <= composition.user_profiles else "managed"}|' + ' '.join(tokens))
            tokens = []
            number += 1
        else:
            tokens.append(token)
    result.append(f'PROFILE|{number}|{"user" if number <= composition.user_profiles else "managed"}|' + ' '.join(tokens))
    return result


def run(ctx):
    path = ctx.paths.nfqws_conf
    if not os.path.isfile(path):
        ctx.console.err('ERROR: nfqws2 config not found: ' + path)
        return 2
    try:
        composition = compose.compose(path, ctx.paths, ctx.environ, config.timeout('compose', ctx.environ))
    except compose.ComposeError:
        ctx.console.err('ERROR: cannot compose the nfqws2 arguments of ' + path)
        return 2
    for line in render(composition):
        ctx.console.out(line)
    return 0
