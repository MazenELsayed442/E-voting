from django.contrib.auth.backends import ModelBackend
from voting.models import CustomUser

class EmailAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(email=username)  # البحث بالبريد الإلكتروني
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            return None
