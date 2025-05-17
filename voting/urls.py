from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import vote_home, save_wallet

from .views import (
    home, vote_home, register, login_view, logout_view,
    send_otp, verify_otp, change_email, resend_otp,
    vote_category, get_candidate_details, verify_totp, vote_candidate,
    send_gmail_otp_ajax, verify_gmail_otp_ajax, verify_google_otp_ajax,login_otp,save_signature,
    
    # Admin views
    admin_dashboard, admin_create_pool, admin_cancel_pool, admin_replace_admin,
    admin_proposals, wallet_connect, admin_view_pool, admin_view_proposal,
    admin_submit_cancel_request, admin_submit_replace_request,
    admin_approve_proposal, admin_reject_proposal, admin_cancel_pool_list,
    
    # New cancellation approval flow
    admin_pending_cancellations, admin_approve_cancellation, admin_reject_cancellation,
    update_transaction_hash
)

urlpatterns = [
    # main pages
    path("", home, name="home"),
    path("vote/", vote_home, name="vote"),

    # accounts management
    path("register/", register, name="register"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    
    # OTP verify
    path("send-otp/", send_otp, name="send_otp"),
    path("verify-otp/", verify_otp, name="verify_otp"),
    path("change_email/", change_email, name="change_email"),
    path("resend-otp/", resend_otp, name="resend_otp"),

    # vote
    path("vote/<str:category>/", vote_category, name="vote_category"),
    path("candidate/<int:candidate_id>/", get_candidate_details, name="get_candidate_details"),
    path("verify_totp/<int:candidate_id>/", verify_totp, name="verify_totp"),
    path("vote/<int:candidate_id>/", vote_candidate, name="vote_candidate"),
    path("login/otp/", login_otp, name="login_otp"),


    # Wallet
    path('save_wallet/', save_wallet, name='save_wallet'),

    # AJAX OTP verification and sending
    path("ajax/send_gmail_otp/", send_gmail_otp_ajax, name="send_gmail_otp_ajax"),
    path("ajax/verify_gmail_otp/", verify_gmail_otp_ajax, name="verify_gmail_otp_ajax"),
    path("ajax/verify_google_otp/", verify_google_otp_ajax, name="verify_google_otp_ajax"),
    path('save-signature/',save_signature, name='save_signature'),
    
    # Admin pages
    path('admin-portal/dashboard/', admin_dashboard, name='admin_dashboard'),
    path('admin-portal/create-pool/', admin_create_pool, name='admin_create_pool'),
    path('admin-portal/cancel-pool/', admin_cancel_pool_list, name='admin_cancel_pool'),  # List all cancelable pools
    path('admin-portal/cancel-pool/<int:pool_id>/', admin_cancel_pool, name='admin_cancel_pool_specific'),  # Cancel specific pool
    path('admin-portal/replace-admin/', admin_replace_admin, name='admin_replace_admin'),
    path('admin-portal/proposals/', admin_proposals, name='admin_proposals'),
    path('admin-portal/wallet-connect/', wallet_connect, name='wallet_connect'),
    path('admin-portal/view-pool/<int:pool_id>/', admin_view_pool, name='admin_view_pool'),
    path('admin-portal/view-proposal/<int:proposal_id>/', admin_view_proposal, name='admin_view_proposal'),
    
    # Admin API endpoints
    path('admin-portal/api/submit-cancel-request/', admin_submit_cancel_request, name='admin_submit_cancel_request'),
    path('admin-portal/api/submit-replace-request/', admin_submit_replace_request, name='admin_submit_replace_request'),
    path('admin-portal/api/approve-proposal/', admin_approve_proposal, name='admin_approve_proposal'),
    path('admin-portal/api/reject-proposal/', admin_reject_proposal, name='admin_reject_proposal'),
    
    # Pool cancellation approval flow
    path('admin-portal/pending-cancellations/', admin_pending_cancellations, name='admin_pending_cancellations'),
    path('admin-portal/approve-cancellation/<int:request_id>/', admin_approve_cancellation, name='admin_approve_cancellation'),
    path('admin-portal/reject-cancellation/<int:request_id>/', admin_reject_cancellation, name='admin_reject_cancellation'),
    path('update-transaction-hash/<int:request_id>/', update_transaction_hash, name='update_transaction_hash'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
