from django.contrib.auth.backends import ModelBackend
from .models import CustomUser

class EmailAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(email=username)  # البحث باستخدام الإيميل
            if user.check_password(password):  # التحقق من صحة كلمة المرور
                return user
        except CustomUser.DoesNotExist:
            return None
