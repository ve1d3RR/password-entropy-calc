import math
import json
from django.shortcuts import render
from .forms import PasswordCheckForm
from .models import PasswordAuditLog
from . import services


def check_password_view(request):
    result = None

    if request.method == 'POST':
        form = PasswordCheckForm(request.POST)

        if form.is_valid():
            password = form.cleaned_data['password']
            target = form.cleaned_data['target']
            hardware_list = form.cleaned_data['hardware']

            # Суммируем мощности всех выбранных видеокарт
            total_hashrate_md5 = sum(gpu.hashrate_md5 for gpu in hardware_list)

            entropy = services.calculate_entropy(password)
            crack_time = services.calculate_crack_time(entropy, total_hashrate_md5)
            is_pwned = services.check_pwned_password(password)

            audit_log = PasswordAuditLog.objects.create(
                target=target,
                password_length=len(password),
                entropy_score=entropy,
                time_to_crack_seconds=crack_time,
                is_pwned=is_pwned
            )
            audit_log.hardware.set(hardware_list)

            # Данные для линейного графика (Прогноз)
            chart_labels = []
            chart_data = []
            alphabet_size = services.get_alphabet_size(password)
            current_len = len(password)

            for i in range(5):
                test_len = current_len + i
                test_entropy = test_len * math.log2(alphabet_size) if alphabet_size > 0 else 0
                test_time = services.calculate_crack_time(test_entropy, total_hashrate_md5)
                chart_labels.append(f"{test_len} симв.")
                chart_data.append(round(test_time, 2))

            # Данные для кругового графика (Доля каждой видеокарты в пуле)
            pie_labels = [gpu.name for gpu in hardware_list]
            pie_data = [gpu.hashrate_md5 for gpu in hardware_list]

            result = {
                'entropy': entropy,
                'crack_time': crack_time,
                'is_pwned': is_pwned,
                'length': len(password),
                'chart_labels': json.dumps(chart_labels),
                'chart_data': json.dumps(chart_data),
                'pie_labels': json.dumps(pie_labels),
                'pie_data': json.dumps(pie_data),
            }
    else:
        form = PasswordCheckForm()

    return render(request, 'audit/check.html', {'form': form, 'result': result})