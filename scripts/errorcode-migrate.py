#!/usr/bin/env python3
"""One-shot migration: give every logical.ErrorResponse call a stable error_code.

Kept in-tree only as the record of how the 166 call sites were classified; the
mapping below is the interesting part, and .golangci.yml's forbidigo rule is what
stops the population growing back. Safe to delete once reviewed.
"""
import pathlib
import re
import sys

# (regex matched against the call's argument text, error code). First match wins,
# so order is significant: specific before general.
RULES = [
    # --- operator supplied something wrong or missing -> config_invalid ---
    (r'^err\.Error\(\)$', 'ErrConfigInvalid'),          # ValidateRole/ValidateSetName/parseMinters
    (r'^"[a-z_]+ is required"', 'ErrConfigInvalid'),
    (r'^"invalid minter set', 'ErrConfigInvalid'),
    (r'^"minter[_ ]set %q does not exist"', 'ErrConfigInvalid'),
    (r'^"minter %q not found in set %q"', 'ErrConfigInvalid'),
    (r'^"minter %q is already retired"', 'ErrConfigInvalid'),
    (r'^"rotation would invalidate the minter set', 'ErrConfigInvalid'),
    (r'^"[a-z_]+ must be', 'ErrConfigInvalid'),
    (r'^"service_account_email must be', 'ErrConfigInvalid'),
    (r'ShortTTLMsg|LongTTLMsg', 'ErrConfigInvalid'),
    (r'must not exceed', 'ErrConfigInvalid'),
    (r'must be <=', 'ErrConfigInvalid'),
    (r'^"minter has no rotation_params', 'ErrConfigInvalid'),
    (r'^"minter capability verification failed', 'ErrConfigInvalid'),
    (r'^"invalid ', 'ErrConfigInvalid'),
    (r'^"unknown ', 'ErrConfigInvalid'),

    # --- this cloud will never support it -> unsupported ---
    (r'^"minter rotation is not supported', 'ErrUnsupported'),

    # --- the role itself ---
    (r'^"role_not_found: role %q does not exist"', 'ErrRoleNotFound'),
    (r'^"role %q does not exist"', 'ErrRoleNotFound'),
    (r'^"role %q is disabled"', 'ErrRoleDisabled'),

    # --- upstream said no, or no minter could ask it ---
    (r'^"no healthy minter', 'ErrUpstreamAuthFailed'),
    (r'^"cannot reconcile', 'ErrUpstreamAuthFailed'),
    (r'^"successor minter failed health check', 'ErrUpstreamAuthFailed'),
    (r'^"successor could not be granted', 'ErrUpstreamAuthFailed'),
    (r'^"minter rotation disabled by GCP org policy', 'ErrUpstreamAuthFailed'),

    # --- an upstream attempt with no status: let the error decide ---
    (r'^"rotation failed', 'CLASSIFY'),
    (r'^"reconcile failed', 'CLASSIFY'),

    # --- our own fault ---
    (r'^"metrics not initialized"', 'ErrInternal'),
    (r'^"stale query failed', 'ErrInternal'),
    (r'^"role saved but slot initialization failed', 'ErrInternal'),
    (r'^"failed to ', 'ErrInternal'),
    (r'^"could not ', 'ErrInternal'),
    (r'^"cannot list ', 'ErrInternal'),
    (r'^"metrics query failed', 'ErrInternal'),
]

CALL = 'logical.ErrorResponse('


def split_args(text):
    """Return (args_text, index_after_close_paren) for a balanced call."""
    depth, i, in_str, esc = 1, 0, False, False
    while i < len(text):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return text[:i], i + 1
        i += 1
    return None, None


def code_for(args):
    flat = ' '.join(args.split())
    for pattern, code in RULES:
        if re.search(pattern, flat):
            return code
    return None


def migrate(path):
    src = path.read_text()
    out, pos, changed, unmatched = [], 0, 0, []
    while True:
        idx = src.find(CALL, pos)
        if idx < 0:
            out.append(src[pos:])
            break
        args, after = split_args(src[idx + len(CALL):])
        if args is None:
            out.append(src[pos:idx + len(CALL)])
            pos = idx + len(CALL)
            continue
        code = code_for(args)
        if code is None:
            unmatched.append(' '.join(args.split())[:90])
            out.append(src[pos:idx + len(CALL) + after])
            pos = idx + len(CALL) + after
            continue
        if code == 'CLASSIFY':
            first = 'credenvelope.Classify(credenvelope.StatusNone, err)'
        else:
            first = 'credenvelope.' + code
        if args.strip() == 'err.Error()':
            new_args = f'{first}, "%s", err.Error()'
        else:
            new_args = f'{first}, {args}'
        out.append(src[pos:idx])
        out.append(f'credenvelope.ErrorResponse({new_args})')
        pos = idx + len(CALL) + after
        changed += 1
    if changed:
        path.write_text(''.join(out))
    return changed, unmatched


def main():
    total, all_unmatched = 0, []
    roots = [pathlib.Path('plugins'), pathlib.Path('pkg')]
    for root in roots:
        for path in sorted(root.rglob('*.go')):
            if path.name.endswith('_test.go'):
                continue
            if path == pathlib.Path('pkg/credenvelope/errors.go'):
                continue
            changed, unmatched = migrate(path)
            total += changed
            for u in unmatched:
                all_unmatched.append(f'{path}: {u}')
    print(f'converted {total} call sites')
    if all_unmatched:
        print(f'\nUNMATCHED ({len(all_unmatched)}) — need a rule or a hand edit:')
        for u in all_unmatched:
            print('  ' + u)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
