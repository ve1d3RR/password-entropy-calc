from django.contrib import admin
from .models import TargetGroup, HardwareRig, PasswordAuditLog

@admin.register(TargetGroup)
class TargetGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')

@admin.register(HardwareRig)
class HardwareRigAdmin(admin.ModelAdmin):
    list_display = ('name', 'power_watts', 'formatted_md5', 'formatted_sha')
    search_fields = ('name',)
    ordering = ['-hashrate_md5']

@admin.register(PasswordAuditLog)
class PasswordAuditLogAdmin(admin.ModelAdmin):
    list_display = ('target', 'password_length', 'entropy_score', 'is_pwned', 'tested_at')