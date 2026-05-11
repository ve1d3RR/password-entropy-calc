from django.db import models
from django.contrib.auth.models import User

class AuditProject(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='projects', verbose_name="Пользователь")
    name = models.CharField(max_length=255, verbose_name="Название проекта (компании)")
    description = models.TextField(blank=True, null=True, verbose_name="Описание проекта")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата создания")

    class Meta:
        verbose_name = "Проект аудита"
        verbose_name_plural = "Проекты аудитов"

    def __str__(self):
        return f"{self.name} (Владелец: {self.user.username})"


class HardwareRig(models.Model):
    """
    Лекция ООП: Инкапсулируем логику форматирования вывода внутри класса.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='hardware', verbose_name="Пользователь")
    name = models.CharField(max_length=255, verbose_name="Название фермы (например: 4x RTX 4090)")
    power_watts = models.IntegerField(verbose_name="Энергопотребление (Ватт)", null=True, blank=True)
    hashrate_md5 = models.BigIntegerField(verbose_name="Скорость перебора MD5 (H/s)")
    hashrate_sha256 = models.BigIntegerField(verbose_name="Скорость перебора SHA-256 (H/s)")

    class Meta:
        verbose_name = "Оборудование для взлома"
        verbose_name_plural = "Оборудование для взлома"

    def formatted_md5(self):
        """Возвращает хэшрейт MD5 в удобном для чтения формате (f-строки)"""
        if self.hashrate_md5 >= 1_000_000_000:
            return f"{self.hashrate_md5 / 1_000_000_000:.1f} GH/s"
        return f"{self.hashrate_md5 / 1_000_000:.1f} MH/s"
    formatted_md5.short_description = "Скорость MD5"
    formatted_md5.admin_order_field = 'hashrate_md5'

    def formatted_sha(self):
        """Возвращает хэшрейт SHA-256 в удобном для чтения формате"""
        if self.hashrate_sha256 >= 1_000_000_000:
            return f"{self.hashrate_sha256 / 1_000_000_000:.1f} GH/s"
        return f"{self.hashrate_sha256 / 1_000_000:.1f} MH/s"
    formatted_sha.short_description = "Скорость SHA-256"
    formatted_sha.admin_order_field = 'hashrate_sha256'

    def __str__(self):
        """Перегрузка оператора строкового представления"""
        if self.power_watts:
            return f"{self.name} [{self.power_watts}W] | {self.formatted_md5()}"
        return f"{self.name} | {self.formatted_md5()}"


class PasswordAuditLog(models.Model):
    project = models.ForeignKey(AuditProject, on_delete=models.CASCADE, related_name='audit_logs', verbose_name="Проект")
    hardware = models.ForeignKey(HardwareRig, on_delete=models.SET_NULL, null=True, verbose_name="Оборудование")
    password_length = models.IntegerField(verbose_name="Длина пароля")
    entropy_score = models.FloatField(verbose_name="Энтропия (бит)")
    time_to_crack_seconds = models.FloatField(verbose_name="Время взлома (секунды)")
    is_pwned = models.BooleanField(default=False, verbose_name="Найден в утечках (Pwned)")
    tested_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата и время проверки")

    class Meta:
        verbose_name = "Журнал проверки"
        verbose_name_plural = "Журналы проверок"

    def __str__(self):
        pwned_status = "УТЕЧКА!" if self.is_pwned else "Безопасно"
        return f"Проверка в {self.project.name} | {self.tested_at.strftime('%d.%m.%Y')} | {pwned_status}"