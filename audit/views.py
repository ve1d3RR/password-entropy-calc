import math
import json
import requests
from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from django.core.cache import cache
from .forms import PasswordCheckForm
from .models import TargetGroup, HardwareRig, PasswordAuditLog
from . import services

# Резервный справочник оборудования для автономной работы
HARDWARE_CATALOG = [
    {"name": "NVIDIA GeForce RTX 5090", "md5": 380_000_000_000, "sha": 50_000_000_000},
    {"name": "NVIDIA GeForce RTX 5080", "md5": 260_000_000_000, "sha": 35_000_000_000},
    {"name": "NVIDIA GeForce RTX 4090", "md5": 164_000_000_000, "sha": 22_000_000_000},
    {"name": "NVIDIA GeForce RTX 3080", "md5": 97_000_000_000, "sha": 12_000_000_000},
    {"name": "AMD Radeon RX 7900 XTX", "md5": 140_000_000_000, "sha": 19_000_000_000},
    {"name": "Apple M3 Ultra", "md5": 125_000_000_000, "sha": 16_000_000_000},
    {"name": "Базовый офисный ноутбук", "md5": 50_000_000, "sha": 1_000_000},
]


def fetch_minerstat_gpus():
    """Загрузка данных из внешнего API Minerstat"""
    api_key = getattr(settings, 'MINERSTAT_API_KEY', '')
    url = "https://api.minerstat.com/v2/hardware"
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    params = {"type": "gpu"}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return []


def gpu_search_api(request):
    """Живой поиск видеокарт по API и локальной базе"""
    query = request.GET.get('q', '').lower().strip()
    if not query:
        return JsonResponse([], safe=False)

    cached_gpus = cache.get('minerstat_gpus')
    if cached_gpus is None:
        cached_gpus = fetch_minerstat_gpus()
        if cached_gpus:
            cache.set('minerstat_gpus', cached_gpus, 3600)
        else:
            cached_gpus = []

    results = []
    for gpu in cached_gpus:
        name = gpu.get('name') or ''
        if query in name.lower():
            specs = gpu.get('specs') or {}
            raw_pwr = specs.get('GPU Power') or '150'
            power = int(''.join(filter(str.isdigit, str(raw_pwr))) or 150)
            results.append({
                'name': name,
                'power': power,
                'md5': power * 450_000_000,
                'sha': power * 60_000_000,
            })

    for item in HARDWARE_CATALOG:
        if query in item['name'].lower() and not any(r['name'] == item['name'] for r in results):
            results.append(item)

    return JsonResponse(results[:15], safe=False)


def check_password_view(request):
    """
    Основная логика анализа пароля.
    Рассчитывает параметры на основе выбранного пула оборудования и его количества.
    """
    result = None
    if request.method == 'POST':
        form = PasswordCheckForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            target = form.cleaned_data['target']
            hardware_list = form.cleaned_data['hardware']
            quantity = form.cleaned_data.get('quantity', 1)

            # Расчет суммарной мощности: (сумма хэшрейтов выбранных карт) * количество систем
            total_md5 = sum(gpu.hashrate_md5 for gpu in hardware_list) * quantity

            entropy = services.calculate_entropy(password)
            crack_time_seconds = services.calculate_crack_time(entropy, total_md5)

            # Преобразование секунд в человекочитаемый формат (дни, месяцы, годы)
            readable_time = services.format_crack_time(crack_time_seconds)

            is_pwned = services.check_pwned_password(password)

            # Определение категории стойкости
            if entropy < 40:
                strength, strength_class = "НИЗКАЯ", "danger"
            elif entropy < 60:
                strength, strength_class = "СРЕДНЯЯ", "warning"
            else:
                strength, strength_class = "ВЫСОКАЯ", "success"

            # Сохранение результатов аудита в БД
            log = PasswordAuditLog.objects.create(
                target=target, password_length=len(password),
                entropy_score=entropy, time_to_crack_seconds=crack_time_seconds, is_pwned=is_pwned
            )
            log.hardware.set(hardware_list)

            # Генерация данных для линейного графика (прогноз)
            labels, values = [], []
            for i in range(6):
                new_len = len(password) + i
                e = new_len * math.log2(services.get_alphabet_size(password))
                labels.append(f"+{i}")
                # Добавляем в график сырые секунды для корректного отображения шкалы
                values.append(services.calculate_crack_time(e, total_md5))

            # Генерация данных для круговой диаграммы (вклад устройств)
            pie_data = []
            for gpu in hardware_list:
                # Вклад считается с учетом множителя пула
                gpu_total = gpu.hashrate_md5 * quantity
                share = (gpu_total / total_md5 * 100) if total_md5 > 0 else 0
                url_name = gpu.name.lower().replace(" ", "-").replace("(", "").replace(")", "")
                pie_data.append({
                    'name': gpu.name,
                    'ghs': round(gpu_total / 1_000_000_000, 1),
                    'percent': round(share, 1),
                    'url': f"https://minerstat.com/hardware/{url_name}",
                    'raw_val': gpu_total
                })

            result = {
                'entropy': entropy,
                'crack_time_display': readable_time,
                'is_pwned': is_pwned,
                'strength': strength,
                'strength_class': strength_class,
                'total_md5_gh': round(total_md5 / 1_000_000_000, 2),
                'chart_labels': json.dumps(labels),
                'chart_data': json.dumps(values),
                'pie_json': json.dumps(pie_data),
            }
    else:
        form = PasswordCheckForm()

    return render(request, 'audit/check.html', {'form': form, 'result': result})