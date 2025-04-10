import pyotp
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

# Custom User Manager
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, username, password, **extra_fields)

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    otp_secret = models.CharField(max_length=16, blank=True, null=True)
    qr_code = models.ImageField(upload_to="qr_codes/", blank=True, null=True)
    is_verified = models.BooleanField(default=False) 

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def save(self, *args, **kwargs):
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
        
        super().save(*args, **kwargs)  # حفظ المستخدم أولًا للحصول على user.id

        if not self.qr_code:
            qr = qrcode.make(self.get_totp_uri())
            buffer = BytesIO()
            qr.save(buffer, format="PNG")
            self.qr_code.save(f"{self.username}_qrcode.png", ContentFile(buffer.getvalue()), save=False)
            
            super().save(update_fields=["qr_code"])  # تحديث qr_code فقط بدون حفظ كل الحقول

    def get_totp_uri(self):
        return f"otpauth://totp/eVoting:{self.email}?secret={self.otp_secret}&issuer=eVoting"

    def verify_otp(self, otp_code):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(otp_code)

    def __str__(self):
        return self.username

# Candidate Model
class Candidate(models.Model):
    CATEGORY_CHOICES = [
        ("President", "President"),
        ("Vice President", "Vice President"),
        ("Secretary", "Secretary"),
    ]
    
    name = models.CharField(max_length=100)
    party = models.CharField(max_length=100, blank=True, null=True)
    votes = models.IntegerField(default=0)  # إضافة حقل الأصوات
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default="President")
    image = models.ImageField(upload_to="candidates/", blank=True, null=True)  # إضافة صورة للمرشح
    description = models.TextField(blank=True, null=True)  # إضافة وصف للمرشح

    def __str__(self):
        return f"{self.name} ({self.party})" if self.party else self.name

    class Meta:
        verbose_name_plural = "Candidates"

# Voter Model
class Voter(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100)
    national_id = models.CharField(max_length=14, unique=True)
    has_voted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} - {self.national_id}"

    class Meta:
        verbose_name_plural = "Voters"

# Category Model
class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)  

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Categories"



from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class EmailAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            # السماح بتسجيل الدخول باستخدام البريد الإلكتروني أو اسم المستخدم
            user = User.objects.filter(email=username).first() or User.objects.filter(username=username).first()
            if user and user.check_password(password):
                return user
        except User.DoesNotExist:
            return None
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
