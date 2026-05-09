from django import forms
from .models import AuditProject, HardwareRig


class PasswordCheckForm(forms.Form):
    """
    Форма для ввода пароля.
    Мы используем обычный forms.Form, а не ModelForm, потому что мы
    категорически НЕ хотим сохранять сам пароль в базу данных!
    """
    password = forms.CharField(
        label="Пароль для проверки",
        # Используем PasswordInput, чтобы символы скрывались звездочками при вводе
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Секретный пароль...'}),
        min_length=1
    )

    project = forms.ModelChoiceField(
        queryset=AuditProject.objects.all(),
        label="Проект аудита (Компания)",
        widget=forms.Select(attrs={'class': 'form-select'}),
        empty_label="Выберите проект..."
    )

    hardware = forms.ModelChoiceField(
        queryset=HardwareRig.objects.all(),
        label="Оборудование злоумышленника",
        widget=forms.Select(attrs={'class': 'form-select'}),
        empty_label="Выберите видеокарту..."
    )