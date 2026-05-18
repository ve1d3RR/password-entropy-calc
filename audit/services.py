import math
import hashlib
import requests
import uuid
from django.conf import settings
from django.core.cache import cache

def get_alphabet_size(password: str) -> int:
    """
    Определяет размер "алфавита" пароля.
    Чем разнообразнее символы, тем сложнее подобрать пароль.
    """
    size = 0
    if any(c.islower() for c in password):
        size += 26  # Строчные английские буквы
    if any(c.isupper() for c in password):
        size += 26  # Заглавные буквы
    if any(c.isdigit() for c in password):
        size += 10  # Цифры
    if any(not c.isalnum() for c in password):
        size += 32  # Спецсимволы (!@#$%^&*)

    # Если пароль пустой или странный, возвращаем минимум 1, чтобы не было ошибки деления на 0
    return size if size > 0 else 1


def calculate_entropy(password: str) -> float:
    """
    Рассчитывает энтропию по формуле Шеннона: E = L * log2(R)
    Где L - длина пароля, R - размер алфавита.
    """
    length = len(password)
    if length == 0:
        return 0.0

    r = get_alphabet_size(password)
    entropy = length * math.log2(r)
    return round(entropy, 2)


def calculate_crack_time(entropy: float, hashrate: int) -> float:
    """
    Рассчитывает время взлома в секундах.
    Количество возможных комбинаций равно 2 в степени энтропии.
    """
    if hashrate <= 0:
        return float('inf')

    combinations = 2 ** entropy
    time_seconds = combinations / hashrate
    return time_seconds


def check_pwned_password(password: str) -> bool:
    """
    Безопасная проверка утечки пароля через API HaveIBeenPwned.
    Использует метод k-Anonymity (отправляем только первые 5 символов хэша).
    """
    # 1. Хэшируем пароль алгоритмом SHA-1 и переводим в верхний регистр
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # 2. Разбиваем хэш на префикс (первые 5 символов) и суффикс (остальное)
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    # 3. Отправляем API запрос, передавая ТОЛЬКО префикс!
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        # Устанавливаем таймаут, чтобы сайт не завис, если API недоступно
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            # API возвращает сотни хэшей, начинающихся на наш префикс.
            # Мы ищем в этом списке наш суффикс.
            hashes = (line.split(':')[0] for line in response.text.splitlines())
            if suffix in hashes:
                return True  # Пароль скомпрометирован!
    except requests.RequestException as e:
        # Если API упало или нет интернета, просто игнорируем, чтобы не ломать сайт
        print(f"Ошибка API: {e}")

    return False  # Пароль безопасен (или не найден)


def format_crack_time(seconds: float) -> str:
    """
    Превращает секунды в читаемый формат: годы, месяцы, дни и т.д.
    """
    if seconds == float('inf'):
        return "Вечность"
    if seconds < 1:
        return "Мгновенно"

    intervals = (
        ('веков', 3153600000),
        ('лет', 31536000),
        ('мес.', 2592000),
        ('дн.', 86400),
        ('час.', 3600),
        ('мин.', 60),
        ('сек.', 1),
    )

    for name, count in intervals:
        value = seconds // count
        if value >= 1:
            return f"{int(value)} {name}"

    return "Мгновенно"


def get_gigachat_token():
    """
    Получает access_token для GigaChat.
    Использует кэширование для оптимизации количества запросов.
    """
    token = cache.get('gigachat_token')
    if token:
        return token

    url = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'RqUID': str(uuid.uuid4()),
        'Authorization': f'Basic {settings.GIGACHAT_AUTH_KEY}'
    }
    payload = {'scope': settings.GIGACHAT_SCOPE}

    try:
        response = requests.post(url, headers=headers, data=payload, verify=True)
        if response.status_code == 200:
            new_token = response.json().get('access_token')
            # Кэшируем токен на 25 минут
            cache.set('gigachat_token', new_token, 1500)
            return new_token
    except Exception as e:
        print(f"Системная ошибка GigaChat Auth: {e}")
    return None


def ask_gigachat(prompt: str) -> str:
    """
    Отправляет текстовый запрос к модели GigaChat и возвращает ответ.
    """
    token = get_gigachat_token()
    if not token:
        return "Сервис рекомендаций временно недоступен."

    url = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions"
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    payload = {
        "model": "GigaChat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 500
    }

    try:
        response = requests.post(url, headers=headers, json=payload, verify=True)
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
    except Exception as e:
        print(f"Системная ошибка GigaChat Query: {e}")
    return "Не удалось получить ответ от нейросети."