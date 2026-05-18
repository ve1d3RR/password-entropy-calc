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

# Резервный справочник оборудования
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
    result = None

    # 1. Получаем факт дня от GigaChat при каждом обновлении страницы
    daily_fact = cache.get('ib_daily_fact')
    if not daily_fact:
        daily_fact = services.ask_gigachat(
            "Напиши один короткий, серьезный научный факт об информационной безопасности или взломе паролей. Не более 15 слов.")
        cache.set('ib_daily_fact', daily_fact, 3600)  # Кэш на час

    if request.method == 'POST':
        form = PasswordCheckForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            target = form.cleaned_data['target']
            cluster_raw = form.cleaned_data.get('cluster_data')

            try:
                selected_hardware = json.loads(cluster_raw)
            except:
                selected_hardware = []

            total_md5 = 0
            pie_data = []
            hardware_objects = []

            for item in selected_hardware:
                gpu, created = HardwareRig.objects.get_or_create(
                    name=item['name'],
                    defaults={
                        'hashrate_md5': item.get('md5', 100_000_000_000),
                        'hashrate_sha256': item.get('sha', 10_000_000_000),
                        'power_watts': item.get('power', 150)
                    }
                )

                count = int(item.get('count', 1))
                gpu_total_power = gpu.hashrate_md5 * count
                total_md5 += gpu_total_power
                hardware_objects.append(gpu)

                url_name = gpu.name.lower().replace(" ", "-").replace("(", "").replace(")", "")
                pie_data.append({
                    'name': f"{gpu.name} (x{count})",
                    'raw_val': gpu_total_power,
                    'ghs': round(gpu_total_power / 1_000_000_000, 1),
                    'url': f"https://minerstat.com/hardware/{url_name}"
                })

            if total_md5 == 0: total_md5 = 1_000_000_000

            entropy = services.calculate_entropy(password)
            crack_time_seconds = services.calculate_crack_time(entropy, total_md5)
            readable_time = services.format_crack_time(crack_time_seconds)
            is_pwned = services.check_pwned_password(password)

            # --- ЗАПРОС РЕКОМЕНДАЦИИ У GIGACHAT ---
            ai_prompt = (f"Пароль пользователя: {password}. Энтропия: {entropy} бит. "
                         f"Дай один профессиональный совет по улучшению этого пароля. "
                         f"Ответь кратко и строго.")
            ai_advice = services.ask_gigachat(ai_prompt)

            log = PasswordAuditLog.objects.create(
                target=target, password_length=len(password),
                entropy_score=entropy, time_to_crack_seconds=crack_time_seconds, is_pwned=is_pwned
            )
            log.hardware.set(hardware_objects)

            labels, values = [], []
            alphabet_size = services.get_alphabet_size(password)
            for i in range(6):
                new_len = len(password) + i
                e = new_len * math.log2(alphabet_size) if alphabet_size > 0 else 0
                labels.append(f"+{i}")
                values.append(services.calculate_crack_time(e, total_md5))

            for p in pie_data:
                p['percent'] = round((p['raw_val'] / total_md5) * 100, 1)

            result = {
                'entropy': entropy,
                'crack_time_display': readable_time,
                'is_pwned': is_pwned,
                'ai_advice': ai_advice,  # Добавляем совет в результат
                'total_md5_gh': round(total_md5 / 1_000_000_000, 2),
                'chart_labels': json.dumps(labels),
                'chart_data': json.dumps(values),
                'pie_json': json.dumps(pie_data),
            }
    else:
        form = PasswordCheckForm()

    return render(request, 'audit/check.html', {
        'form': form,
        'result': result,
        'daily_fact': daily_fact  # Передаем факт дня
    })