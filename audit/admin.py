import requests
from django.contrib import admin, messages
from .models import AuditProject, HardwareRig, PasswordAuditLog


@admin.action(description="📥 Спарсить актуальные видеокарты (Minerstat API)")
def fetch_gpus_from_api(modeladmin, request, queryset):
    url = "https://api.minerstat.com/v2/hardware"
    try:
        response = requests.get(url, timeout=5)
        gpus_data = response.json()

        if isinstance(gpus_data, list):
            only_gpus = [item for item in gpus_data if isinstance(item, dict) and item.get('type') == 'gpu'][:20]
        else:
            raise ValueError("API вернуло неожиданный формат")
    except Exception as e:
        modeladmin.message_user(request, f"API недоступно. Использован Fallback.", messages.WARNING)
        only_gpus = [
            {"name": "Nvidia RTX 4090", "specs": {"power": 450}},
            {"name": "Nvidia RTX 4080", "specs": {"power": 320}},
            {"name": "AMD Radeon RX 7900 XTX", "specs": {"power": 355}},
            {"name": "Nvidia RTX 3090", "specs": {"power": 350}},
        ]

    try:
        count = 0
        for gpu in only_gpus:
            name = gpu.get('name')
            power = gpu.get('specs', {}).get('power', 150)

            md5_hash = int(power * 450_000_000)
            sha_hash = int(power * 60_000_000)

            obj, created = HardwareRig.objects.get_or_create(
                name=name,
                defaults={
                    'user': request.user,
                    'power_watts': power,  # Оставляем только ватты!
                    'hashrate_md5': md5_hash,
                    'hashrate_sha256': sha_hash,
                }
            )
            if created:
                count += 1

        modeladmin.message_user(request, f"Успешно добавлено {count} новых видеокарт!", messages.SUCCESS)
    except Exception as e:
        modeladmin.message_user(request, f"Ошибка при сохранении: {e}", messages.ERROR)


@admin.register(AuditProject)
class AuditProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'created_at')
    search_fields = ('name', 'user__username', 'description')
    list_filter = ('created_at',)


@admin.register(HardwareRig)
class HardwareRigAdmin(admin.ModelAdmin):
    list_display = ('name', 'power_watts', 'formatted_md5', 'formatted_sha')
    search_fields = ('name',)
    actions = [fetch_gpus_from_api]
    ordering = ['-hashrate_md5']


@admin.register(PasswordAuditLog)
class PasswordAuditLogAdmin(admin.ModelAdmin):
    list_display = ('project', 'password_length', 'entropy_score', 'is_pwned', 'tested_at')
    list_filter = ('is_pwned', 'project')