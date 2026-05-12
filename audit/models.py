from django.db import models
from django.contrib.auth.models import User


class TargetGroup(models.Model):
    name = models.CharField(max_length=255, verbose_name="Категория цели (например: Соцсети, Банкинг)")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата создания")

    class Meta:
        verbose_name = "Группа целей"
        verbose_name_plural = "Группы целей"

    def __str__(self):
        return self.name


class HardwareRig(models.Model):
    name = models.CharField(max_length=255, verbose_name="Название оборудования")
    power_watts = models.IntegerField(verbose_name="Энергопотребление (Ватт)", null=True, blank=True)
    hashrate_md5 = models.BigIntegerField(verbose_name="Скорость перебора MD5 (H/s)")
    hashrate_sha256 = models.BigIntegerField(verbose_name="Скорость перебора SHA-256 (H/s)")

    class Meta:
        verbose_name = "Оборудование для взлома"
        verbose_name_plural = "Оборудование для взлома"

    def formatted_md5(self):
        if self.hashrate_md5 >= 1_000_000_000:
            return f"{self.hashrate_md5 / 1_000_000_000:.1f} GH/s"
        return f"{self.hashrate_md5 / 1_000_000:.1f} MH/s"

    formatted_md5.short_description = "Скорость MD5"
    formatted_md5.admin_order_field = 'hashrate_md5'

    def formatted_sha(self):
        if self.hashrate_sha256 >= 1_000_000_000:
            return f"{self.hashrate_sha256 / 1_000_000_000:.1f} GH/s"
        return f"{self.hashrate_sha256 / 1_000_000:.1f} MH/s"

    formatted_sha.short_description = "Скорость SHA-256"
    formatted_sha.admin_order_field = 'hashrate_sha256'

    def __str__(self):
        if self.power_watts:
            return f"{self.name} [{self.power_watts}W] | {self.formatted_md5()}"
        return f"{self.name} | {self.formatted_md5()}"


class PasswordAuditLog(models.Model):
    target = models.ForeignKey(TargetGroup, on_delete=models.CASCADE, verbose_name="Группа цели")
    hardware = models.ManyToManyField(HardwareRig, verbose_name="Использованное оборудование")
    password_length = models.IntegerField(verbose_name="Длина пароля")
    entropy_score = models.FloatField(verbose_name="Энтропия (бит)")
    time_to_crack_seconds = models.FloatField(verbose_name="Время взлома (секунды)")
    is_pwned = models.BooleanField(default=False, verbose_name="Найден в утечках")
    tested_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата проверки")

    class Meta:
        verbose_name = "Журнал проверки"
        verbose_name_plural = "Журналы проверок"

    def __str__(self):
        return f"Аудит: {self.target.name} | {self.tested_at.strftime('%d.%m.%Y')}"