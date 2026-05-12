from django import forms
from .models import TargetGroup, HardwareRig

"""
 Форма для ввода пароля.
 Мы используем обычный forms.Form, а не ModelForm, потому что мы
 категорически НЕ хотим сохранять сам пароль в базу данных!
 """
class PasswordCheckForm(forms.Form):
    password = forms.CharField(
        label="Пароль для проверки",
        widget=forms.TextInput(attrs={'class': 'form-control', 'type': 'text', 'placeholder': 'Введите пароль...'}),
        min_length=1
    )

    target = forms.ModelChoiceField(
        queryset=TargetGroup.objects.all(),
        label="Группа (Категория цели)",
        widget=forms.Select(attrs={'class': 'form-select'}),
        empty_label="Выберите категорию..."
    )

    hardware = forms.ModelMultipleChoiceField(
        queryset=HardwareRig.objects.all(),
        label="Сборка оборудования (Пул)",
        widget=forms.SelectMultiple(attrs={'class': 'form-select'}),
    )