from django.shortcuts import render
from .forms import PasswordCheckForm
from .models import PasswordAuditLog
from . import services


def check_password_view(request):
    """Главная страница калькулятора"""
    result = None

    # Если пользователь нажал кнопку "Проверить"
    if request.method == 'POST':
        form = PasswordCheckForm(request.POST)

        # Django сам проверяет, чтобы не было хакерских инъекций (Валидация)
        if form.is_valid():
            # 1. Достаем безопасные данные
            password = form.cleaned_data['password']
            project = form.cleaned_data['project']
            hardware = form.cleaned_data['hardware']

            # 2. Вызываем наши функции из сервисного слоя (Математика + API)
            entropy = services.calculate_entropy(password)
            crack_time = services.calculate_crack_time(entropy, hardware.hashrate_md5)  # Считаем для MD5
            is_pwned = services.check_pwned_password(password)

            # 3. Сохраняем отчет в БД. Обратите внимание: пароль сюда НЕ передается!
            audit_log = PasswordAuditLog.objects.create(
                project=project,
                hardware=hardware,
                password_length=len(password),
                entropy_score=entropy,
                time_to_crack_seconds=crack_time,
                is_pwned=is_pwned
            )

            # 4. Упаковываем результаты, чтобы показать их на экране
            result = {
                'entropy': entropy,
                'crack_time': crack_time,
                'is_pwned': is_pwned,
                'length': len(password),
            }
    else:
        # Если пользователь просто зашел на сайт, показываем пустую форму
        form = PasswordCheckForm()

    # Отправляем форму и результаты в HTML-шаблон (его мы создадим следующим шагом)
    return render(request, 'audit/check.html', {'form': form, 'result': result})