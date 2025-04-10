from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser

# نموذج تسجيل المستخدم الجديد
class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser  # استخدم الموديل المخصص
        fields = ("username", "email", "password1", "password2")



from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import get_user_model

User = get_user_model()

class LoginForm(AuthenticationForm):
    username = forms.CharField(
        label="Email or Username",
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"class": "form-control"})
    )

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get("username")
        password = cleaned_data.get("password")

        if username and password:
            user = User.objects.filter(email=username).first() or User.objects.filter(username=username).first()
            if user:
                cleaned_data["username"] = user.username  # تحويل البريد إلى اسم المستخدم الفعلي
            else:
                raise forms.ValidationError("❌ No account found with this email or username.")

        return cleaned_data

        
        # البحث عن المستخدم عن طريق البريد الإلكتروني
        user = CustomUser.objects.filter(email=email).first()
        if user:
            cleaned_data["username"] = user.username  # تحويل البريد إلى اسم المستخدم الفعلي
        return cleaned_data


class OTPVerificationForm(forms.Form):
    otp = forms.CharField(label="Enter OTP", max_length=6, required=True)
