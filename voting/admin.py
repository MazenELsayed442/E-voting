# voting/admin.py (Updated)

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser, Candidate, Voter, Category, PoolCancellationRequest # Import your models from this app

# --- Admin Configuration for CustomUser ---
@admin.register(CustomUser) # Use decorator for cleaner registration
class CustomUserAdmin(BaseUserAdmin):
    """
    Customizes the admin interface for the CustomUser model.
    Displays the user_type field for easy identification and filtering.
    """
    # Add 'user_type' to the list display
    list_display = (
        'email',      # Using email as primary identifier now
        'username',   # Still useful to display
        'first_name',
        'last_name',
        'user_type',  # <<< Added user_type here
        'is_staff',
        'is_verified',
        'is_active',
    )

    # Add 'user_type' to the filters
    list_filter = BaseUserAdmin.list_filter + (
        'is_verified',
        'user_type',  # <<< Added user_type here
    )

    # Add fields to be searchable
    search_fields = BaseUserAdmin.search_fields + ('email',) # email is already searchable via BaseUserAdmin

    # Add 'user_type' to the editing form ('fieldsets')
    # Ensure 'Custom Fields' section exists or add it
    # We reuse the structure from the previous example
    fieldsets = BaseUserAdmin.fieldsets + (
        # Add 'user_type' to this section
        ('Custom Fields', {'fields': ('user_type', 'is_verified', 'otp_secret', 'qr_code')}),
        # Add voted_candidates if using ManyToManyField
        # ('Voting', {'fields': ('voted_candidates',)}),
    )

    # Add 'user_type' to the 'add user' form if desired (it has a default though)
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        (None, {'fields': ('email', 'first_name', 'last_name')}), # Core fields
        ('Roles', {'fields': ('user_type', 'is_verified')}),     # Add user_type here
    )

    # Keep sensitive/generated fields read-only
    readonly_fields = BaseUserAdmin.readonly_fields + ('qr_code', 'otp_secret')

# --- Admin Configuration for Candidate (Unchanged from previous version) ---
@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'votes')
    list_filter = ('category',)
    search_fields = ('name', 'description', 'category')
    # readonly_fields = ('votes',)

# --- Admin Configuration for Voter (Unchanged from previous version) ---
@admin.register(Voter)
class VoterAdmin(admin.ModelAdmin):
    list_display = ('user', 'get_wallet_address') # Example
    search_fields = ('user__username', 'user__email', 'wallet_address') # Example

    @admin.display(description='Wallet Address')
    def get_wallet_address(self, obj):
        return getattr(obj, 'wallet_address', 'N/A') # Example

# Register Category with admin
@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)

# Register PoolCancellationRequest with admin
@admin.register(PoolCancellationRequest)
class PoolCancellationRequestAdmin(admin.ModelAdmin):
    list_display = ('pool_id', 'initiator', 'approver', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'created_at')
    search_fields = ('pool_id', 'initiator__username', 'initiator__email', 'approver__username', 'approver__email')
    readonly_fields = ('created_at', 'updated_at', 'transaction_hash')
    fieldsets = (
        ('Request Information', {
            'fields': ('pool_id', 'reason', 'status')
        }),
        ('Admin Information', {
            'fields': ('initiator', 'approver')
        }),
        ('Blockchain Information', {
            'fields': ('transaction_hash',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )