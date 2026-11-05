"""Small HTTPS recipes inspired by dpi-detector, unrelated to strategy selection.

Reference: Runnin4ik/dpi-detector, MIT,
8d6d25a733f82e97a2aad8435072f8a1e3e43958 (TLS scanner and TCP16 observations).
No upstream code/dependencies, insecure SSL, mass raw-IP scans or tuning imported.
"""

TARGETS = {
    'youtube': ('YouTube', 'https://www.youtube.com/robots.txt'),
    'discord': ('Discord API', 'https://discord.com/api/v10/gateway'),
    'telegram': ('Telegram', 'https://telegram.org/'),
    'claude': ('Claude', 'https://claude.ai/'),
    'tcp16': ('TCP 64 KiB', 'https://speed.cloudflare.com/__down?bytes=65536'),
}
IP_URLS = {'ipv4': 'https://api.ipify.org?format=json', 'ipv6': 'https://api6.ipify.org?format=json'}
CANARY = 'https://www.gstatic.com/generate_204'
URLS = frozenset([value[1] for value in TARGETS.values()] + list(IP_URLS.values()) + [CANARY])
ATTRIBUTION = 'Методика TLS1.2/TLS1.3 и наблюдений TCP16: Runnin4ik/dpi-detector (MIT). Это не автоподбор стратегий.'
