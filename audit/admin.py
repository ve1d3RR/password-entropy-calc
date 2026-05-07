from django.contrib import admin
from .models import AuditProject, HardwareRig, PasswordAuditLog

@admin.register(AuditProject)
class AuditProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'created_at')
    search_fields = ('name', 'user__username', 'description')
    list_filter = ('created_at',)

@admin.register(HardwareRig)
class HardwareRigAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'hashrate_md5', 'hashrate_sha256')
    search_fields = ('name', 'user__username')

@admin.register(PasswordAuditLog)
class PasswordAuditLogAdmin(admin.ModelAdmin):
    list_display = ('project', 'password_length', 'entropy_score', 'is_pwned', 'tested_at')
    list_filter = ('is_pwned', 'project')
    search_fields = ('project__name',)