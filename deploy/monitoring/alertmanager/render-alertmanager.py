#!/usr/bin/env python3
"""Render alertmanager.yml from the committed template and private secret files.

Runs as ExecStartPre of zecblock-alertmanager.service, as the service user,
which can read the 0640 root:zecblock-alertmanager secret files. Writes the
result 0600 into the service's RuntimeDirectory (tmpfs, gone at stop).

Secrets are never printed. The Telegram bot token is not copied into the
rendered file at all: Alertmanager reads it from bot_token_file at send time.

Usage: render-alertmanager.py --template T --secrets-dir D --templates-dir D2 --out F
"""
import argparse
import os
import re
import sys
import tempfile

PLACEHOLDER = re.compile(r'\$\{([A-Z_]+)\}')
HEARTBEAT_BLOCK = re.compile(r'^# HEARTBEAT-BEGIN\n.*?^# HEARTBEAT-END\n', re.S | re.M)


def read_env_file(path):
    values = {}
    with open(path, encoding='utf-8') as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            key, sep, value = line.partition('=')
            if not sep or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', key.strip()):
                raise ValueError(f'{path}:{n}: expected KEY=value')
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            values[key.strip()] = value
    return values


def render(template, *, chat_id, secrets_dir, templates_dir, heartbeat):
    if not re.fullmatch(r'-?[0-9]{1,20}', chat_id or ''):
        raise ValueError('TELEGRAM_CHAT_ID must be an integer chat id')
    for name, value in (('secrets dir', secrets_dir), ('templates dir', templates_dir)):
        if not re.fullmatch(r'/[A-Za-z0-9._/-]+', value):
            raise ValueError(f'{name} must be a plain absolute path')
    if heartbeat:
        text = template.replace('# HEARTBEAT-BEGIN\n', '').replace('# HEARTBEAT-END\n', '')
    else:
        text = HEARTBEAT_BLOCK.sub('', template)
    values = {
        'TELEGRAM_CHAT_ID': chat_id,
        'SECRETS_DIR': secrets_dir.rstrip('/'),
        'TEMPLATES_DIR': templates_dir.rstrip('/'),
        'WATCHDOG_RECEIVER': 'heartbeat' if heartbeat else 'blackhole',
    }

    def sub(match):
        key = match.group(1)
        if key not in values:
            raise ValueError(f'unknown placeholder ${{{key}}}')
        return values[key]

    return PLACEHOLDER.sub(sub, text)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--template', required=True)
    ap.add_argument('--secrets-dir', default='/etc/zecblock-monitor')
    ap.add_argument('--templates-dir', default='/etc/zecblock-monitor/alertmanager')
    ap.add_argument('--out', required=True)
    args = ap.parse_args(argv)
    env = read_env_file(os.path.join(args.secrets_dir, 'telegram.env'))
    token_file = os.path.join(args.secrets_dir, 'telegram-bot-token')
    if not os.path.isfile(token_file) or os.path.getsize(token_file) == 0:
        raise SystemExit('telegram-bot-token is missing or empty')
    heartbeat = os.path.isfile(os.path.join(args.secrets_dir, 'heartbeat-url'))
    with open(args.template, encoding='utf-8') as f:
        text = render(f.read(), chat_id=env.get('TELEGRAM_CHAT_ID', ''), secrets_dir=args.secrets_dir,
                      templates_dir=args.templates_dir, heartbeat=heartbeat)
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.alertmanager.', dir=out_dir)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, args.out)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print(f'rendered {args.out} (heartbeat receiver: {"on" if heartbeat else "off"})')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        sys.exit(f'render-alertmanager: {exc}')
