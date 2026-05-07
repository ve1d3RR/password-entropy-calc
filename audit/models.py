from django.db import models
from django.contrib.auth.models import User


class AuditProject(models.Model):
    """Модель проекта (компании/отдела), для которого и соответственно проводится аудит"""
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
    """Модель конфигурации оборудования (GPU-фермы) для расчета времени "Brute-Force" """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='hardware', verbose_name="Пользователь")
    name = models.CharField(max_length=255, verbose_name="Название фермы (например: 4x RTX 4090)")
    # Хэшрейт измеряется в огромных числах (миллиарды операций в секунду), поэтому используем BigIntegerField
    hashrate_md5 = models.BigIntegerField(verbose_name="Скорость перебора MD5 (H/s)")
    hashrate_sha256 = models.BigIntegerField(verbose_name="Скорость перебора SHA-256 (H/s)")

    class Meta:
        verbose_name = "Оборудование для взлома"
        verbose_name_plural = "Оборудование для взлома"

    def __str__(self):
        return self.name


class PasswordAuditLog(models.Model):
    """
    Журнал проверок паролей.
    САМОЕ ВАЖНОЕ!: Мы не храним сам пароль в базе данных для соблюдения стандартов безопасности!
    """
    project = models.ForeignKey(AuditProject, on_delete=models.CASCADE, related_name='audit_logs',
                                verbose_name="Проект")
    # Если оборудование удалят, запись о проверке останется, просто поле hardware станет пустым (null=True)
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