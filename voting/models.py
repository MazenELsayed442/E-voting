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

# models.py (With user_type field added)



# Make sure Candidate model is defined above or imported if needed
# class Candidate(models.Model): ...

class CustomUser(AbstractUser):
    """
    Custom user model using email as the username field,
    with OTP verification, QR code generation, and user type differentiation.
    """
    # --- Existing Fields ---
    email = models.EmailField(
        unique=True,
        help_text='Required. Unique email address for login and communication.'
    )
    # Increased length for standard base32 secret compatibility
    otp_secret = models.CharField(
        max_length=32,
        blank=True,
        null=True,
        help_text='Secret key for TOTP generation (auto-generated if blank).'
    )
    qr_code = models.ImageField(
        upload_to="qr_codes/",
        blank=True,
        null=True,
        help_text='QR code image for TOTP provisioning (auto-generated if blank).'
    )
    is_verified = models.BooleanField(
        default=False,
        help_text='Designates whether the user has completed the initial OTP verification.'
    )
    
    # Assuming ManyToMany based on previous context - add if needed
    voted_candidates = models.ManyToManyField(
        'Candidate',
        blank=True,
        related_name='voters',
        help_text='Candidates this user has already voted for.'
    )
    
    # Add wallet address field for blockchain integration
    wallet_address = models.CharField(
        max_length=42,  # Ethereum addresses are 42 characters (0x + 40 hex chars)
        blank=True,
        null=True,
        help_text='Ethereum wallet address for blockchain integration.'
    )
    
    # --- USER TYPE FIELD ---
    USER_TYPE_CHOICES = (
        ('voter', 'Voter'),           # Standard user who can vote
        ('admin', 'Administrator'),    # User with special admin views/permissions
        # Add more roles as needed (e.g., 'staff', 'auditor')
    )
    user_type = models.CharField(
        max_length=10,
        choices=USER_TYPE_CHOICES,
        default='voter', # Default new users to the 'voter' type
        help_text='Designates the role or type of the user.'
    )
    # --- END NEW FIELD ---

    # --- Existing Configuration ---
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"] # Keep 'username' required if you still use it elsewhere, otherwise remove

    # --- Existing Methods ---
    def save(self, *args, **kwargs):
        """
        Overrides save to auto-generate OTP secret and QR code if they don't exist.
        """
        # Generate OTP secret only if it's not already set
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32(length=32) # Use standard length

        # Determine if this is a new user or an update
        is_new = self._state.adding

        # Save the user instance first (especially needed for new users to get an ID)
        # If updating, don't save qr_code yet if we need to generate it
        update_fields = kwargs.get('update_fields')
        if update_fields and 'qr_code' in update_fields:
            # Temporarily remove qr_code from update_fields if we need to generate it
             kwargs['update_fields'] = [f for f in update_fields if f != 'qr_code']

        super().save(*args, **kwargs) # Save user data (excluding QR code if generating)

        # Generate QR code only if it doesn't exist and we have an otp_secret
        # Use self.pk to ensure the user has been saved and has an ID
        if not self.qr_code and self.otp_secret and self.pk:
            try:
                # Generate QR code URI
                totp_uri = self.get_totp_uri()
                qr_image = qrcode.make(totp_uri)
                buffer = BytesIO()
                qr_image.save(buffer, format="PNG")
                # Use self.pk for a unique filename
                file_name = f"user_{self.pk}_qrcode.png"
                # Save the QR code image file to the qr_code field
                # save=False prevents recursion by calling save() again immediately
                self.qr_code.save(file_name, ContentFile(buffer.getvalue()), save=False)

                # Now, explicitly save *only* the qr_code field to the database
                # Use super().save() to avoid triggering this override again
                super().save(update_fields=["qr_code"])
            except Exception as e:
                # Handle potential errors during QR code generation/saving
                # Log the error or handle it appropriately
                print(f"Error generating/saving QR code for user {self.pk}: {e}")


    def get_totp_uri(self):
        """Generates the provisioning URI for TOTP apps."""
        # Ensure email and issuer name are properly encoded if needed,
        # but typically safe characters are used here.
        return f"otpauth://totp/eVoting:{self.email}?secret={self.otp_secret}&issuer=eVoting"

    def verify_otp(self, otp_code):
        """Verifies a given OTP code against the user's secret."""
        if not self.otp_secret:
            return False # Cannot verify if secret doesn't exist
        totp = pyotp.TOTP(self.otp_secret)
        # Use verify with valid_window for more tolerance
        return totp.verify(otp_code, valid_window=1)

    def __str__(self):
        """String representation of the user."""
        # Using email as it's the primary identifier now
        return self.email

# Remember to define or import Candidate model if using voted_candidates field
# class Candidate(models.Model): ...

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

# Pool Cancellation Request Model
class PoolCancellationRequest(models.Model):
    """
    Model to track pool cancellation requests from admins.
    A pool can be canceled when at least 2 admins approve the request.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('executed', 'Executed')  # When the cancellation has been executed on the blockchain
    ]
    
    # The pool ID on the blockchain to be canceled
    pool_id = models.IntegerField()
    
    # Reason for cancellation
    reason = models.TextField()
    
    # Admin who initiated the cancellation request
    initiator = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name='initiated_cancellations'
    )
    
    # Admin who approved the cancellation (can be null if not yet approved)
    approver = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name='approved_cancellations',
        null=True, 
        blank=True
    )
    
    # Status of the request
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='pending'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Transaction hash when the cancellation is executed on the blockchain
    transaction_hash = models.CharField(max_length=66, blank=True, null=True)
    
    class Meta:
        verbose_name = "Pool Cancellation Request"
        verbose_name_plural = "Pool Cancellation Requests"
    
    def __str__(self):
        return f"Cancellation Request for Pool #{self.pool_id} by {self.initiator.username}"
    
    @property
    def is_approved(self):
        """Check if the request is approved."""
        return self.status == 'approved' or self.status == 'executed'
    
    @property
    def can_be_approved(self):
        """
        Check if the request can be approved (pending and not created by current admin).
        """
        from django.contrib.auth import get_user_model
        from django.shortcuts import get_object_or_404
        
        # This gets called in template context, so we need to check against the current user
        # We need to use a method that doesn't require request object
        # In a template, this would be used as: {% if request.can_be_approved_by:user %}
        return self.status == 'pending'
    
    def can_be_approved_by(self, user):
        """
        Check if the request can be approved by the specified admin.
        Returns False if the user is the one who initiated the request.
        """
        return self.status == 'pending' and self.initiator != user
    
    @property
    def can_be_executed(self):
        """
        Check if the cancellation can be executed on the blockchain.
        """
        return self.status == 'approved' and not self.transaction_hash


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

# CancellationRequest Model
class CancellationRequest(models.Model):
    """Model to track cancellation requests for voting pools."""
    pool_id = models.IntegerField(
        help_text='ID of the pool requested to be cancelled.'
    )
    reason = models.TextField(
        help_text='Reason provided for cancellation.'
    )
    requested_by = models.ForeignKey(
        'CustomUser',
        on_delete=models.CASCADE,
        related_name='cancellation_requests',
        help_text='Admin who requested the cancellation.'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text='When the cancellation was requested.'
    )
    is_executed = models.BooleanField(
        default=False,
        help_text='Whether the cancellation has been executed on the blockchain.'
    )
    transaction_hash = models.CharField(
        max_length=66,  # Ethereum transaction hashes are 66 characters (0x + 64 hex chars)
        blank=True,
        null=True,
        help_text='Blockchain transaction hash if executed.'
    )
    
    def __str__(self):
        return f"Cancel request for pool #{self.pool_id} by {self.requested_by.email}"
    
    class Meta:
        verbose_name = "Cancellation Request"
        verbose_name_plural = "Cancellation Requests"
        ordering = ['-created_at']
