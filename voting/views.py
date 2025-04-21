import json
import random
from io import BytesIO

# Third-party imports
import pyotp
import qrcode
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (
    authenticate,
    get_backends,
    get_user_model,
    login,
    logout,
)
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render, get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# Local application imports
from .forms import CustomUserCreationForm, LoginForm
from .models import Candidate, CustomUser, Voter
from .utils.contract_utils import get_vote_count, submit_vote




def home(request):
    categories = ["President", "Vice President", "Secretary"]
    return render(request, "voting/home.html", {"categories": categories})


def register(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)

        if form.is_valid():
            user = form.save(commit=False)  
            user.is_verified = False
            user.otp_secret = pyotp.random_base32()  # OTP Secret
            user.save()  

            
            totp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(user.email, issuer_name="E-Voting System")
            qr = qrcode.make(totp_uri)
            buffer = BytesIO()
            qr.save(buffer, format="PNG")

            
            user.qr_code.save(f"otp_qr_{user.id}.png", ContentFile(buffer.getvalue()), save=True)

            
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')

            
            request.session["user_id"] = user.id
            request.session["email"] = user.email

            messages.success(request, "✅ Registration successful! Scan the QR code with Google Authenticator and verify via OTP sent to your email.")
            return redirect("send_otp")  

        else:
            messages.error(request, "❌ Registration failed. Please check the form.")

    else:
        form = CustomUserCreationForm()

    return render(request, "voting/register.html", {"form": form})


def verified_required(view_func):
    @login_required(login_url="/login/")
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_verified:
            messages.error(request, "❌ You need to verify your account before accessing this page.")
            return redirect("home")  
        return view_func(request, *args, **kwargs)
    return _wrapped_view


User = get_user_model()

def login_view(request):
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)

        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]

            user = authenticate(request, username=username, password=password)

            if user:
                request.session["pending_user_id"] = user.id
                return redirect("login_otp")
            else:
                messages.error(request, "Invalid login credentials.")

        else:
            print("Form is not valid:", form.errors)

    else:
        form = LoginForm()

    return render(request, "voting/login.html", {"form": form})


def verify_totp(request, candidate_id):
    user_id = request.session.get("pending_user_id")

    if not user_id:
        messages.error(request, "❌ Session expired. Please log in again.")
        return redirect("login")

    user = get_object_or_404(CustomUser, id=user_id)
    candidate = get_object_or_404(Candidate, id=candidate_id) 

    if request.method == "POST":
        otp_code = request.POST.get("otp")
        totp = pyotp.TOTP(user.otp_secret)

        if totp.verify(otp_code):
            
            user.voted_candidates.add(candidate)  
            user.save()

            del request.session["pending_user_id"]  

            messages.success(request, f"✅ Your vote for {candidate.name} has been recorded!")
            return redirect("home")  
        else:
            del request.session["pending_user_id"]  
            messages.error(request, "❌ Invalid OTP. Please log in again to receive a new code.")
            return redirect("login")  

    return render(request, "voting/verify_totp.html", {"candidate": candidate})


@login_required(login_url="/login/")
def logout_view(request):
    logout(request)
    messages.success(request, "✅ Logout successful!")
    return redirect("home")

def send_otp(request):
    # Retrieve email from session
    email = request.session.get("email")
    
    # If email is not in session, redirect to login
    if not email:
        messages.error(request, "❌ Email not available, please log in.")
        return redirect("login")

    # Generate a new OTP code
    otp_code = str(random.randint(100000, 999999))

    # Store OTP in session
    request.session["otp_code"] = otp_code

    # Send OTP via email
    send_mail(
        "Your OTP Code",
        f"Your OTP code is: {otp_code}",
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

    messages.success(request, "✅ OTP has been sent to your email.")
    return redirect("verify_otp")


def verify_otp(request): 
    email = request.session.get("email")
    user_id = request.session.get("user_id")

    if not email or not user_id:
        messages.error(request, "❌ Session expired. Please log in again.")
        return redirect("login")

    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        entered_gmail_otp = request.POST.get("gmail_otp")
        entered_authenticator_otp = request.POST.get("authenticator_otp")
        stored_gmail_otp = request.session.get("otp_code")

        
        if entered_gmail_otp != stored_gmail_otp:
            del request.session["otp_code"]  
            messages.error(request, "❌ Incorrect OTP from email. A new OTP has been sent.")
            return redirect("resend_otp")  

        
        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(entered_authenticator_otp):
            messages.error(request, "❌ Incorrect OTP from Google Authenticator. Please try again.")
            return redirect("verify_otp")

        
        user.is_verified = True
        user.save()

        
        backend = settings.AUTHENTICATION_BACKENDS[0]  
        login(request, user, backend=backend)

        
        del request.session["otp_code"]
        del request.session["user_id"]
        del request.session["email"]

        messages.success(request, "✅ Verification successful! You are now logged in.")
        return redirect("home")

    return render(request, "voting/verify_otp.html", {"email": email})

    
# Resend OTP
def resend_otp(request):
    email = request.session.get("email")

    if not email:
        messages.error(request, "❌ Email not found.")
        return redirect("send_otp")

    otp_code = str(random.randint(100000, 999999))
    request.session["otp_code"] = otp_code

    send_mail(
        "New OTP Code",
        f"Your new OTP code is: {otp_code}",
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

    messages.success(request, "✅ A new OTP has been sent to your email.")
    return redirect("verify_otp")

# Change email
def change_email(request):
    request.session.pop("email", None)
    request.session.pop("otp_code", None)
    messages.info(request, "✉️ Please enter a new email.")
    return redirect("send_otp")


@login_required(login_url="/login/")
@verified_required
def vote_home(request):
    categories = ["President", "Vice President", "Secretary"]
    return render(request, "voting/vote_home.html", {"categories": categories})


CANDIDATES = {
    "President": [
        {"id": 1, "name": "Ahmed", "image": "/media/ahmed.jpg", "description": "description", "votes": 0},
        {"id": 2, "name": "Sara", "image": "/media/sara.jpg", "description": "description", "votes": 0},
    ],
    "Vice President": [
        {"id": 3, "name": "Mohamed", "image": "/media/mohamed.jpg", "description": "description", "votes": 0},
        {"id": 4, "name": "Nora", "image": "/media/nora.jpg", "description": "description", "votes": 0},
    ],
    "Secretary": [
        {"id": 5, "name": "Omar", "image": "/media/omar.jpg", "description": "description", "votes": 0},
        {"id": 6, "name": "Laila", "image": "/media/laila.jpg", "description": "description", "votes": 0},
    ],
}


@login_required(login_url="/login/")
@verified_required
def vote_category(request, category):
    allowed_categories = ["President", "Vice President", "Secretary"]

    if category not in allowed_categories:
        messages.error(request, "❌ Invalid category selected.")
        return redirect("vote_home")

    candidates = CANDIDATES.get(category, [])

    
    for candidate in candidates:
        candidate["image_url"] = settings.MEDIA_URL + candidate["image"]

    if request.method == "POST":
        email = request.session.get("email")
        if not email:
           messages.error(request, "❌ You must be logged in to vote.")
           return redirect("login")

        candidate_id = request.POST.get("candidate_id")
        if not candidate_id:
            messages.error(request, "❌ Please select a candidate before voting.")
            return redirect("vote_category", category=category)

        candidate_id = int(candidate_id)
        candidate = next((c for c in candidates if c["id"] == candidate_id), None)

        if not candidate:
            messages.error(request, "❌ Invalid candidate selected.")
            return redirect("vote_category", category=category)

        candidate["votes"] += 1
        messages.success(request, f"✅ Voting successful for {candidate['name']}!")
        return redirect("vote_home")

    return render(request, "voting/vote_category.html", {"category": category, "candidates": candidates})

 

def get_candidate_details(request, candidate_id):
    candidate = get_object_or_404(Candidate, id=candidate_id)

    # Load ABI from the correct path (inside blockchain/ folder)
    try:
        with open("blockchain/artifacts/contracts/Voting.sol/Voting.json", "r") as f:
            contract_abi = json.load(f)["abi"]
    except FileNotFoundError:
        contract_abi = []  # Fallback if ABI not found

    context = {
        "candidate": candidate,
        "contract_abi": json.dumps(contract_abi),  # Convert to string
        "contract_address": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    }

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'name': candidate.name,
            'image_url': candidate.image.url,
            'description': candidate.description,
        })

    return render(request, "voting/candidate_details.html", context)

def vote_candidate(request, candidate_id):
    candidate = get_object_or_404(Candidate, id=candidate_id)  
    return render(request, "voting/vote_candidate.html", {"candidate": candidate})


def confirm_vote(request, candidate_id):
    candidate = get_object_or_404(Candidate, id=candidate_id)
    
    if request.method == "POST":
        candidate.votes += 1
        candidate.save()

        return render(request, "voting/vote_success.html", {"candidate": candidate})

    return redirect("vote_home")


def save_wallet(request):
    if request.method == "POST":
        data = json.loads(request.body)
        wallet_address = data.get("wallet_address")
        
        
        print(f"Received wallet address: {wallet_address}")  
        
        return JsonResponse({"message": "Wallet saved successfully!"})
    return JsonResponse({"error": "Invalid request"}, status=400)


@login_required
def send_gmail_otp_ajax(request):
    email = request.user.email
    otp_code = str(random.randint(100000, 999999))
    request.session["voting_otp"] = otp_code

    send_mail(
        "Voting OTP Code",
        f"Your OTP code for voting is: {otp_code}",
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

    return JsonResponse({"success": True, "message": "✅ OTP sent to your email."})


@csrf_exempt
@login_required
def verify_gmail_otp_ajax(request):
    data = json.loads(request.body)
    entered_otp = data.get("otp")
    stored_otp = request.session.get("voting_otp")

    if entered_otp == stored_otp:
        return JsonResponse({"success": True})
    else:
        return JsonResponse({"success": False})


@csrf_exempt
@login_required
def verify_google_otp_ajax(request):
    data = json.loads(request.body)
    entered_otp = data.get("otp")
    user = request.user
    totp = pyotp.TOTP(user.otp_secret)

    if totp.verify(entered_otp):
        return JsonResponse({"success": True})
    else:
        return JsonResponse({"success": False})


def login_otp(request):
    user_id = request.session.get("pending_user_id")

    if not user_id:
        messages.error(request, "Session expired. Please try again.")
        return redirect("login")

    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        entered_otp = request.POST.get("otp")
        totp = pyotp.TOTP(user.otp_secret)

        if totp.verify(entered_otp):
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            del request.session["pending_user_id"]
            messages.success(request, "Login successful.")
            return redirect("vote")  # Use the correct name for the vote page here
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, "voting/login_otp.html", {"email": user.email})


def save_signature(request):
    if request.method == "POST":
        data = json.loads(request.body)
        wallet = data.get("wallet")
        signature = data.get("signature")
        print("Wallet:", wallet)
        print("Signature:", signature)
        

        return JsonResponse({"status": "success"})
    return JsonResponse({"status": "invalid request"}, status=400)

### 4/20/2025
def vote_count(request):
    # Get vote count (GET request)
    if request.method == "GET":
        candidate = request.GET.get("candidate", "Alice")  # Default to Alice
        count = get_vote_count(candidate)
        return JsonResponse({candidate: count})
    return JsonResponse({"error": "Invalid request method"})

# Submit vote (POST request)
@csrf_exempt  # Remove this in production and handle CSRF properly
def submit_vote_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            candidate = data.get("candidate")
            private_key = data.get("private_key")  # Security risk! See note below
            
            # Validate input
            if not candidate or not private_key:
                return JsonResponse({"error": "Missing parameters"}, status=400)
            
            txn_hash = submit_vote(candidate, private_key)
            return JsonResponse({"txn_hash": txn_hash})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)


