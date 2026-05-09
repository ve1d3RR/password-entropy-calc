import math
import json
from django.shortcuts import render
from .forms import PasswordCheckForm
from .models import PasswordAuditLog
from . import services


def check_password_view(request):
    """Главная страница калькулятора"""
    result = None

    if request.method == 'POST':
        form = PasswordCheckForm(request.POST)

        if form.is_valid():
            password = form.cleaned_data['password']
            project = form.cleaned_data['project']
            hardware = form.cleaned_data['hardware']

            entropy = services.calculate_entropy(password)
            crack_time = services.calculate_crack_time(entropy, hardware.hashrate_md5)
            is_pwned = services.check_pwned_password(password)

            # Сохраняем отчет в БД
            PasswordAuditLog.objects.create(
                project=project,
                hardware=hardware,
                password_length=len(password),
                entropy_score=entropy,
                time_to_crack_seconds=crack_time,
                is_pwned=is_pwned
            )

            # === НОВЫЙ БЛОК: ГЕНЕРАЦИЯ ДАННЫХ ДЛЯ ГРАФИКА ===
            chart_labels = []
            chart_data = []
            alphabet_size = services.get_alphabet_size(password)
            current_len = len(password)

            # Считаем, сколько займет взлом, если добавить к паролю еще от 0 до +4 символов
            for i in range(5):
                test_len = current_len + i
                # Считаем тестовую энтропию
                test_entropy = test_len * math.log2(alphabet_size) if alphabet_size > 0 else 0
                # Считаем тестовое время
                test_time = services.calculate_crack_time(test_entropy, hardware.hashrate_md5)

                chart_labels.append(f"{test_len} симв.")
                chart_data.append(round(test_time, 2))

            result = {
                'entropy': entropy,
                'crack_time': crack_time,
                'is_pwned': is_pwned,
                'length': len(password),
                # Упаковываем списки в JSON, чтобы JavaScript смог их прочитать
                'chart_labels': json.dumps(chart_labels),
                'chart_data': json.dumps(chart_data),
            }
    else:
        form = PasswordCheckForm()

    return render(request, 'audit/check.html', {'form': form, 'result': result})