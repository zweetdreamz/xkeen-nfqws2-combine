"""Safe probe summaries: classify errors, never publish raw process output.

Xray can echo credentials, encrypted settings and token-bearing WS paths.
Only fixed messages and HTTP status numbers are allowed out of this module.
"""
import re


CURL_ERRORS = {
    0: 'запрос завершён',
    5: 'не удалось разрешить имя прокси',
    6: 'не удалось разрешить имя назначения',
    7: 'не удалось подключиться к локальному SOCKS',
    28: 'таймаут соединения или передачи',
    35: 'ошибка TLS при HTTPS-запросе через туннель',
    52: 'пустой ответ через туннель',
    55: 'ошибка отправки через туннель',
    56: 'ошибка чтения из туннеля',
    60: 'сертификат тестового HTTPS-сайта не прошёл проверку',
    67: 'отказ авторизации',
    97: 'ошибка согласования SOCKS; смотрите причину Xray',
}


def curl_reason(code):
    return CURL_ERRORS.get(code, 'ошибка curl; смотрите код завершения')


def xray_issues(text):
    if not isinstance(text, str):
        return []
    lowered = text[-8192:].lower()
    patterns = (
        ('websocket: bad handshake', 'WS: сервер отклонил WebSocket Upgrade'),
        ('unexpected http response', 'WS/HTTP: неожиданный ответ сервера'),
        ('certificate signed by unknown authority', 'TLS: неизвестный центр сертификации'),
        ('certificate has expired', 'TLS: истёк срок действия сертификата'),
        ('certificate is valid for', 'TLS: имя сертификата не совпадает с SNI'),
        ('doesn\'t contain any ip sans', 'TLS: сертификат не содержит IP SAN'),
        ('tls: handshake failure', 'TLS: сервер отклонил handshake'),
        ('remote error: tls', 'TLS: удалённая сторона вернула ошибку'),
        ('connection refused', 'TCP/UDP: соединение отклонено'),
        ('no route to host', 'Маршрут: нет пути до сервера'),
        ('network is unreachable', 'Маршрут: сеть недоступна'),
        ('no such host', 'DNS: имя сервера не разрешилось'),
        ('server misbehaving', 'DNS: ошибка ответа резолвера'),
        ('i/o timeout', 'Соединение: таймаут ввода/вывода'),
        ('context deadline exceeded', 'Соединение: превышено время ожидания'),
        ('connection reset by peer', 'Соединение: сброс удалённой стороной'),
        ('unexpected eof', 'Соединение: преждевременное закрытие потока'),
        ('invalid user', 'Авторизация: сервер отклонил пользователя'),
        ('authentication failed', 'Авторизация: сервер отклонил подключение'),
        ('failed to load config', 'Xray: конфигурация не загрузилась'),
        ('failed to parse', 'Xray: ошибка разбора конфигурации'),
        ('unknown transport protocol', 'Xray: неизвестный транспорт'),
    )
    result = [message for marker, message in patterns if marker in lowered]
    # Status phrases can be reported without exposing the header, URL or body.
    for code in re.findall(r'\b([45]\d\d)\s+(?:forbidden|not found|bad request|unauthorized|bad gateway|service unavailable|too many requests)\b', lowered):
        message = 'HTTP сервера/WS Upgrade: ' + code
        if message not in result:
            result.append(message)
    return result[:12]
