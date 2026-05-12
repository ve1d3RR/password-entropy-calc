from django import forms
from .models import TargetGroup, HardwareRig

"""
 Форма для ввода пароля.
 Мы используем обычный forms.Form, а не ModelForm, потому что мы
 категорически НЕ хотим сохранять сам пароль в базу данных!
 """
class PasswordCheckForm(forms.Form):
    password = forms.CharField(
        label="Тестовый пароль",
        widget=forms.TextInput(attrs={'class': 'form-control', 'type': 'text', 'placeholder': 'Введите пароль...'}),
    )
    target = forms.ModelChoiceField(
        queryset=TargetGroup.objects.all(),
        label="Объект атаки",
        widget=forms.Select(attrs={'class': 'form-select'}),
        empty_label="Выберите тип цели..."
    )
    hardware = forms.ModelMultipleChoiceField(
        queryset=HardwareRig.objects.all(),
        label="Состав вычислительного пула",
        widget=forms.SelectMultiple(attrs={'class': 'form-select'}),
    )
    # НОВОЕ ПОЛЕ: Множитель для идентичного оборудования
    quantity = forms.IntegerField(
        label="Количество таких систем в пуле",
        initial=1,
        min_value=1,
        widget=forms.NumberInput(attrs={'class': 'form-control'})
    )