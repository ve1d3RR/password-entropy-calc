import requests
from django.contrib import admin, messages
from .models import TargetGroup, HardwareRig, PasswordAuditLog

@admin.action(description="Загрузить список актуальных видеокарт (2025 год)")
def load_top_2025_gpus(modeladmin, request, queryset):
    top_gpus = [
        {"name": "NVIDIA GeForce RTX 5090", "power": 600, "md5": 380_000_000_000, "sha": 50_000_000_000},
        {"name": "NVIDIA GeForce RTX 5080", "power": 400, "md5": 260_000_000_000, "sha": 35_000_000_000},
        {"name": "NVIDIA GeForce RTX 4090", "power": 450, "md5": 164_000_000_000, "sha": 22_000_000_000},
        {"name": "NVIDIA RTX 6000 Ada", "power": 300, "md5": 155_000_000_000, "sha": 20_000_000_000},
        {"name": "AMD Radeon RX 7900 XTX", "power": 355, "md5": 140_000_000_000, "sha": 19_000_000_000},
        {"name": "Apple M3 Ultra", "power": 150, "md5": 125_000_000_000, "sha": 16_000_000_000},
        {"name": "NVIDIA GeForce RTX 4080 Super", "power": 320, "md5": 115_000_000_000, "sha": 15_000_000_000},
        {"name": "AMD Radeon RX 7900 XT", "power": 315, "md5": 110_000_000_000, "sha": 14_000_000_000},
        {"name": "NVIDIA GeForce RTX 4070 Ti Super", "power": 285, "md5": 92_000_000_000, "sha": 12_000_000_000},
        {"name": "AMD Radeon RX 7800 XT", "power": 263, "md5": 85_000_000_000, "sha": 11_000_000_000},
        {"name": "Apple M3 Max", "power": 80, "md5": 70_000_000_000, "sha": 9_000_000_000},
        {"name": "NVIDIA GeForce RTX 4070 Super", "power": 220, "md5": 65_000_000_000, "sha": 8_500_000_000},
        {"name": "AMD Radeon RX 7700 XT", "power": 245, "md5": 58_000_000_000, "sha": 7_500_000_000},
        {"name": "NVIDIA GeForce RTX 4060 Ti", "power": 160, "md5": 42_000_000_000, "sha": 5_500_000_000},
        {"name": "Базовый офисный ноутбук", "power": 45, "md5": 50_000_000, "sha": 1_000_000},
    ]

    try:
        count = 0
        for gpu in top_gpus:
            obj, created = HardwareRig.objects.get_or_create(
                name=gpu['name'],
                defaults={
                    'power_watts': gpu['power'],
                    'hashrate_md5': gpu['md5'],
                    'hashrate_sha256': gpu['sha'],
                }
            )
            if created:
                count += 1
        modeladmin.message_user(request, f"Успешно загружено {count} новых конфигураций.", messages.SUCCESS)
    except Exception as e:
        modeladmin.message_user(request, f"Ошибка базы данных: {e}", messages.ERROR)

@admin.register(TargetGroup)
class TargetGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')

@admin.register(HardwareRig)
class HardwareRigAdmin(admin.ModelAdmin):
    list_display = ('name', 'power_watts', 'formatted_md5', 'formatted_sha')
    search_fields = ('name',)
    actions = [load_top_2025_gpus]
    ordering = ['-hashrate_md5']

@admin.register(PasswordAuditLog)
class PasswordAuditLogAdmin(admin.ModelAdmin):
    list_display = ('target', 'password_length', 'entropy_score', 'is_pwned', 'tested_at')