from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import vote_home, save_wallet

from .views import (
    home, vote_home, register, login_view, logout_view,
    send_otp, verify_otp, change_email, resend_otp,
    vote_category, get_candidate_details, verify_totp, vote_candidate,
    send_gmail_otp_ajax, verify_gmail_otp_ajax, verify_google_otp_ajax,login_otp,save_signature
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
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
