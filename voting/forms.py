from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model
from .models import CustomUser

User = get_user_model()

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ("username", "email", "password1", "password2")


class LoginForm(AuthenticationForm):
    username = forms.CharField(
        label="Email or Username",
        widget=forms.TextInput(attrs={"class": "form-control"})
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
            # حاول إيجاد المستخدم بواسطة البريد أولاً ثم اسم المستخدم
            user = CustomUser.objects.filter(email=username).first() or CustomUser.objects.filter(username=username).first()
            if user:
                # عيّن username الفعلي للمصادقة
                cleaned_data["username"] = user.username
            else:
                raise forms.ValidationError("❌ No account found with this email or username.")

        return cleaned_data


class OTPVerificationForm(forms.Form):
    otp = forms.CharField(
        label="Enter OTP",
        max_length=6,
        required=True,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "6-digit code"})
    )
