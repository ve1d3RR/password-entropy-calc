from django import forms
from .models import TargetGroup

class PasswordCheckForm(forms.Form):
    password = forms.CharField(
        label="Контрольный пароль",
        widget=forms.TextInput(attrs={'class': 'form-control', 'type': 'text', 'placeholder': 'Введите пароль...'}),
    )
    target = forms.ModelChoiceField(
        queryset=TargetGroup.objects.all(),
        label="Объект атаки",
        widget=forms.Select(attrs={'class': 'form-select'}),
        empty_label="Выберите тип цели..."
    )
    # Скрытое поле для передачи данных о составе кластера из JS в Python
    cluster_data = forms.CharField(widget=forms.HiddenInput(), required=False)