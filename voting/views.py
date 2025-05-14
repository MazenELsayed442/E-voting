import json
import random
from io import BytesIO
import time
import logging
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
from .utils.contract_utils import get_vote_count, submit_vote, get_web3, get_contract, get_pool_details, get_pool_count, get_voting_contract, get_admin_contract, get_voting_contract_address, get_admin_contract_address, create_pool
from .utils.blockchain_monitor import BlockchainMonitor

logger = logging.getLogger(__name__)


def home(request):
    """Home page view that shows voting status and results for voters"""
    # Import blockchain utilities
    from .utils.contract_utils import (
        get_web3, get_voting_contract, get_pool_count, 
        get_pool_details, get_vote_count
    )
    from .utils.blockchain_monitor import BlockchainMonitor
    import datetime
    
    # Basic context - will be enhanced with blockchain data
    context = {
        "blockchain_connected": False
    }
    
    # Add admin-specific context
    if request.user.is_authenticated and request.user.user_type == 'admin':
        context["is_admin"] = True
        context["admin_message"] = "Welcome to the administration portal. Please use the Admin Dashboard to manage the voting system."
        return render(request, "voting/home.html", context)
    
    # For voters and anonymous users, fetch blockchain data
    active_pools = []
    blockchain_connection_failed = False
    
    try:
        web3 = get_web3()
        
        if web3.is_connected():
            context["blockchain_connected"] = True
            
            # Check for blockchain reset
            reset_detected, deleted_count = BlockchainMonitor.process_blockchain_connection(web3)
            if reset_detected and request.user.is_authenticated:
                messages.warning(request, f"Blockchain network was restarted. Previous voting data has been cleared.")
            
            # Always sync database with blockchain to ensure consistency
            sync_database_with_blockchain()
            
            # Get contract and pool count
            voting_contract = get_voting_contract()
            pool_count = get_pool_count()
            
            # Only continue with blockchain data if there are pools
            if pool_count > 0:
                # Fetch all pools
                for pool_id in range(pool_count):
                    try:
                        # Get pool details
                        pool_details = voting_contract.functions.getPoolDetails(pool_id).call()
                        id, category, candidates, start_time, end_time, status = pool_details
                        
                        # Only include active pools (status 1)
                        if status == 1:  # Active
                            # Get votes for each candidate
                            candidate_votes = []
                            total_votes = 0
                            
                            for candidate in candidates:
                                votes = voting_contract.functions.getVotes(pool_id, candidate).call()
                                total_votes += votes
                                candidate_votes.append({
                                    'name': candidate,
                                    'votes': votes
                                })
                            
                            # Calculate vote percentages
                            if total_votes > 0:
                                for candidate_data in candidate_votes:
                                    candidate_data['percentage'] = round((candidate_data['votes'] / total_votes) * 100)
                            else:
                                # If no votes yet, show 0% for all candidates
                                for candidate_data in candidate_votes:
                                    candidate_data['percentage'] = 0
                            
                            # Get user's voting status for this pool
                            has_voted = False
                            if request.user.is_authenticated:
                                try:
                                    has_voted = voting_contract.functions.hasVotedInPool(pool_id, request.user.wallet_address).call()
                                except:
                                    # If wallet is not connected or other error, default to not voted
                                    pass
                            
                            # Add to active pools
                            active_pools.append({
                                'id': id,
                                'category': category,
                                'candidates': candidate_votes,
                                'start_time': start_time,
                                'end_time': end_time,
                                'has_voted': has_voted,
                                'total_votes': total_votes
                            })
                    except Exception as e:
                        print(f"Error getting details for pool {pool_id}: {e}")
            else:
                # No pools found in blockchain - but we're still connected to blockchain
                context["blockchain_connected"] = True
                context["no_pools"] = True
                active_pools = []
        else:
            blockchain_connection_failed = True
    except Exception as e:
        print(f"Error connecting to blockchain: {e}")
        blockchain_connection_failed = True
    
    # Fall back to database ONLY if blockchain connection failed, NOT if there are just no active pools
    if blockchain_connection_failed:
        context["blockchain_connected"] = False
        # Use database data for display
        categories = Candidate.objects.values_list('category', flat=True).distinct()
        
        # Only proceed if there are categories in the database
        if categories:
            for category in categories:
                candidates = Candidate.objects.filter(category=category)
                
                # Only proceed if there are candidates in this category
                if candidates.exists():
                    # Calculate total votes in this category
                    total_votes = sum(c.votes for c in candidates)
                    
                    # Prepare candidate data with percentages
                    candidate_votes = []
                    for candidate in candidates:
                        percentage = round((candidate.votes / total_votes) * 100) if total_votes > 0 else 0
                        candidate_votes.append({
                            'name': candidate.name,
                            'votes': candidate.votes,
                            'percentage': percentage
                        })
                    
                    # Check if user has voted in this category
                    has_voted = False
                    if request.user.is_authenticated:
                        has_voted = request.user.voted_candidates.filter(category=category).exists()
                    
                    # Dummy timestamps - 3 days from now for voting end
                    current_time = datetime.datetime.now().timestamp()
                    end_timestamp = current_time + (3 * 24 * 60 * 60)  # 3 days from now
                    
                    # Add to active pools
                    active_pools.append({
                        'id': len(active_pools),
                        'category': category,
                        'candidates': candidate_votes,
                        'start_time': int(current_time),
                        'end_time': int(end_timestamp),
                        'has_voted': has_voted,
                        'total_votes': total_votes
                    })
    
    # Add active pools to context
    context['active_pools'] = active_pools
    
    return render(request, "voting/home.html", context)


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
        otp_code = request.POST.get("otp", "").strip()
        totp = pyotp.TOTP(user.otp_secret)

        # Debug logging (you can remove in production)
        now_ts = time.time()
        logger.debug(f"[DEBUG] Server UNIX time: {now_ts} ({time.ctime(now_ts)})")
        if totp.verify(otp_code, valid_window=1):
            user.voted_candidates.add(candidate)
            user.save()

            # only delete after a successful vote
            del request.session["pending_user_id"]

            messages.success(request, f"✅ Your vote for {candidate.name} has been recorded!")
            return redirect("home")
        else:
            # optional: allow retry by not deleting on first failure
            messages.error(request, "❌ Invalid OTP. Please try again.")
            return redirect("verify_totp", candidate_id=candidate_id)

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
        entered_gmail_otp        = request.POST.get("gmail_otp",       "").strip()
        entered_authenticator_otp = request.POST.get("authenticator_otp","").strip()
        stored_gmail_otp         = request.session.get("otp_code")

        # 1) Verify email OTP
        if entered_gmail_otp != stored_gmail_otp:
            # clean up and force resend
            del request.session["otp_code"]
            messages.error(request, "❌ Incorrect email OTP. A new code has been sent.")
            return redirect("resend_otp")

        # 2) Verify TOTP with drift window
        totp = pyotp.TOTP(user.otp_secret)
        logger.debug(f"TOTP now={totp.now()} server_time={int(time.time())}")
        if not totp.verify(entered_authenticator_otp, valid_window=1):
            messages.error(request, "❌ Incorrect Google Authenticator code. Please try again.")
            return redirect("verify_otp")

        # 3) Success!
        user.is_verified = True
        user.save()

        backend = settings.AUTHENTICATION_BACKENDS[0]
        login(request, user, backend=backend)

        # cleanup all session keys
        for key in ("otp_code", "user_id", "email"):
            if key in request.session:
                del request.session[key]

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


def non_admin_required(view_func):
    """Decorator to ensure admin users cannot access voter-specific views."""
    def _wrapped_view(request, *args, **kwargs):
        # First check if user is authenticated
        if not request.user.is_authenticated:
            return redirect('login')
            
        # Then check if user is verified
        if not request.user.is_verified:
            messages.error(request, "❌ You need to verify your account before accessing this page.")
            return redirect("home")
            
        # Finally check if user is an admin
        if request.user.user_type == 'admin':
            messages.error(request, "❌ Admins cannot access voting functions.")
            return redirect("admin_dashboard")
            
        # If all checks pass, proceed to the view
        return view_func(request, *args, **kwargs)
    return _wrapped_view

@login_required(login_url="/login/")
@verified_required
@non_admin_required
def vote_home(request):
    """Home page view that shows available voting categories for voters"""
    # Import blockchain utilities
    from .utils.contract_utils import (
        get_web3, get_voting_contract, get_pool_count, 
        get_pool_details
    )
    from .utils.blockchain_monitor import BlockchainMonitor
    import datetime
    
    # Initialize empty categories list
    categories = []
    blockchain_connected = False
    current_time = datetime.datetime.now().timestamp()
    
    # Try to get data from the blockchain first
    try:
        web3 = get_web3()
        
        if web3.is_connected():
            blockchain_connected = True
            
            # Check for blockchain reset
            reset_detected, deleted_count = BlockchainMonitor.process_blockchain_connection(web3)
            if reset_detected:
                messages.warning(request, f"Blockchain network was restarted. Previous voting data has been cleared.")
            
            # Always sync database with blockchain to ensure consistency
            sync_database_with_blockchain()
            
            # Get contract and pool count
            voting_contract = get_voting_contract()
            pool_count = get_pool_count()
            
            # Only continue with blockchain data if there are pools
            if pool_count > 0:
                # Fetch all pools
                for pool_id in range(pool_count):
                    try:
                        # Get pool details
                        pool_details = voting_contract.functions.getPoolDetails(pool_id).call()
                        id, category, candidates, start_time, end_time, status = pool_details
                        
                        # Consider a pool active if:
                        # 1. It has status "Active" (1), OR
                        # 2. It has status "Pending" (0) but the current time is within its time range
                        is_time_active = start_time <= current_time <= end_time
                        
                        if status == 1 or (status == 0 and is_time_active):
                            # Add category to list if not already present
                            if category not in categories:
                                categories.append(category)
                                
                    except Exception as e:
                        print(f"Error getting details for pool {pool_id}: {e}")
    except Exception as e:
        print(f"Error connecting to blockchain: {e}")
    
    # If categories are empty (blockchain connection failed or no active pools),
    # fall back to database which should be in sync with blockchain at this point
    if not categories:
        # Fetch distinct categories from the database
        db_categories = Candidate.objects.values_list('category', flat=True).distinct()
        categories = list(db_categories)
    
    # If still no categories, provide empty list instead of defaults
    # We no longer want to show hardcoded categories
    if not categories:
        categories = []
        messages.info(request, "No active voting categories available at this time.")
    
    return render(request, "voting/vote_home.html", {"categories": categories})




@login_required(login_url="/login/")
@verified_required
@non_admin_required
def vote_category(request, category):
    """Vote for a candidate in the specified category"""
    # Import blockchain utilities
    from .utils.contract_utils import (
        get_web3, get_voting_contract, get_pool_count
    )
    from .utils.blockchain_monitor import BlockchainMonitor
    import datetime
    
    # Initialize allowed categories
    allowed_categories = []
    blockchain_connected = False
    current_time = datetime.datetime.now().timestamp()
    
    # First, try to get allowed categories from blockchain
    try:
        web3 = get_web3()
        
        if web3.is_connected():
            blockchain_connected = True
            
            # Check for blockchain reset
            reset_detected, deleted_count = BlockchainMonitor.process_blockchain_connection(web3)
            if reset_detected:
                messages.warning(request, f"Blockchain network was restarted. Previous voting data has been cleared.")
                return redirect("vote_home")  # Redirect to vote home to show fresh categories
            
            # Get contract and pool count
            voting_contract = get_voting_contract()
            pool_count = get_pool_count()
            
            # Only continue with blockchain data if there are pools
            if pool_count > 0:
                # Fetch all pools
                for pool_id in range(pool_count):
                    try:
                        # Get pool details
                        pool_details = voting_contract.functions.getPoolDetails(pool_id).call()
                        id, pool_category, candidates, start_time, end_time, status = pool_details
                        
                        # Consider a pool active if:
                        # 1. It has status "Active" (1), OR
                        # 2. It has status "Pending" (0) but the current time is within its time range
                        is_time_active = start_time <= current_time <= end_time
                        
                        if status == 1 or (status == 0 and is_time_active):
                            # Add category to list if not already present
                            if pool_category not in allowed_categories:
                                allowed_categories.append(pool_category)
                                
                    except Exception as e:
                        print(f"Error getting details for pool {pool_id}: {e}")
    except Exception as e:
        print(f"Error connecting to blockchain: {e}")
    
    # If blockchain is connected but this category isn't in the blockchain,
    # clear it from the database to prevent stale data access
    if blockchain_connected and allowed_categories and category not in allowed_categories:
        # Clean up any database candidates for this category
        deleted = Candidate.objects.filter(category=category).delete()[0]
        if deleted > 0:
            messages.warning(request, f"Category '{category}' is no longer active on the blockchain.")
        return redirect("vote_home")
    
    # If no categories from blockchain, get from database
    if not allowed_categories:
        # Try to sync the database with blockchain first
        sync_database_with_blockchain()
        
        db_categories = Candidate.objects.values_list('category', flat=True).distinct()
        allowed_categories = list(db_categories)
    
    # If still no categories, use default
    if not allowed_categories:
        allowed_categories = ["President", "Vice President", "Secretary"]
    
    if category not in allowed_categories:
        messages.error(request, "❌ Invalid category selected.")
        return redirect("vote_home")

    # جلب المرشحين من قاعدة البيانات حسب الفئة
    candidates = Candidate.objects.filter(category=category)
    
    # If no candidates found for this category
    if not candidates.exists():
        messages.error(request, f"❌ No candidates found for category '{category}'.")
        return redirect("vote_home")

    if request.method == "POST":
        candidate_id = request.POST.get("candidate_id")
        if not candidate_id:
            messages.error(request, "❌ Please select a candidate before voting.")
            return redirect("vote_category", category=category)

        # تأكد من أن المرشح موجود وينتميت للفئة نفسها
        candidate = get_object_or_404(Candidate, id=candidate_id, category=category)
        candidate.votes += 1
        candidate.save()

        messages.success(request, f"✅ Voting successful for {candidate.name}!")
        return redirect("vote_home")

    return render(request, "voting/vote_category.html", {
        "category": category,
        "candidates": candidates,
    })
 


@non_admin_required
def get_candidate_details(request, candidate_id):
    
    candidate = get_object_or_404(Candidate, id=candidate_id)

    
    try:
        with open("blockchain/artifacts/contracts/Voting.sol/Voting.json", "r") as f:
            contract_data = json.load(f)
            contract_abi = contract_data.get("abi", [])
    except FileNotFoundError:
        contract_abi = []

    
    contract_address = getattr(settings, "VOTING_CONTRACT_ADDRESS", None)
    if not contract_address:
        
        raise RuntimeError("VOTING_CONTRACT_ADDRESS is not set in settings.py")

    
    context = {
        "candidate": candidate,
        "contract_abi": json.dumps(contract_abi),
        "contract_address": contract_address,
        
        
    }

    
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        response_data = {
            "name": candidate.name,
            "description": candidate.description,
            "category": candidate.category,
        }
        # Only add image URL if the image exists
        if candidate.image and candidate.image.name:
            response_data["image_url"] = candidate.image.url
        else:
            response_data["image_url"] = None
        return JsonResponse(response_data)

    return render(request, "voting/candidate_details.html", context)

@non_admin_required
def vote_candidate(request, candidate_id):
    candidate = get_object_or_404(Candidate, id=candidate_id)  
    return render(request, "voting/vote_candidate.html", {"candidate": candidate})


@non_admin_required
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
        
        # حفظ عنوان المحفظة في قاعدة البيانات للمستخدم الحالي
        user = request.user
        user.wallet_address = wallet_address
        user.save(update_fields=['wallet_address'])
        
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

# Admin Views
def admin_required(view_func):
    """Decorator to ensure only admin users can access admin views."""
    @login_required(login_url="/login/")
    @verified_required
    def _wrapped_view(request, *args, **kwargs):
        if request.user.user_type != 'admin':
            messages.error(request, "❌ You don't have permission to access this page.")
            return redirect("home")
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def sync_database_with_blockchain():
    """Synchronize the database candidates with blockchain data"""
    from .utils.contract_utils import get_web3, get_voting_contract, get_pool_count
    from .models import Candidate
    import datetime
    
    try:
        web3 = get_web3()
        
        if web3.is_connected():
            try:
                # First, clear ALL existing candidates to start fresh
                # This ensures we don't have any stale data
                Candidate.objects.all().delete()
                
                # Get contract and count of pools
                voting_contract = get_voting_contract()
                pool_count = get_pool_count()
                
                # Store existing categories to track which ones to keep
                blockchain_categories = set()
                
                # Flag to track if we actually found and added any data
                synced_data = False
                
                # Get current time for checking pool status
                current_time = datetime.datetime.now().timestamp()
                
                # Fetch pool details for all pools
                for pool_id in range(pool_count):
                    try:
                        # Get pool details
                        pool_details = voting_contract.functions.getPoolDetails(pool_id).call()
                        id, category, candidates, start_time, end_time, status = pool_details
                        
                        # Consider a pool active if:
                        # 1. It has status "Active" (1), OR
                        # 2. It has status "Pending" (0) but the current time is within its time range
                        is_time_active = start_time <= current_time <= end_time
                        
                        # Only process active or eligible pools
                        if status == 1 or (status == 0 and is_time_active):
                            # Add category to our set of blockchain categories
                            blockchain_categories.add(category)
                            
                            # For each candidate in the pool, update or create in database
                            for candidate_name in candidates:
                                # Get vote count from blockchain
                                try:
                                    vote_count = voting_contract.functions.getVotes(pool_id, candidate_name).call()
                                except Exception as e:
                                    print(f"Error getting votes for {candidate_name}: {e}")
                                    vote_count = 0
                                    
                                # Create candidate in database - we know it doesn't exist because we cleared all
                                candidate = Candidate.objects.create(
                                    name=candidate_name,
                                    category=category,
                                    description='',
                                    votes=vote_count
                                )
                                
                                synced_data = True
                                
                    except Exception as e:
                        print(f"Error getting details for pool {pool_id}: {e}")
                
                print(f"Blockchain sync complete. Synced {len(blockchain_categories)} categories and {Candidate.objects.count()} candidates.")
                return synced_data
                
            except Exception as e:
                print(f"Error connecting to contract: {e}")
                return False
        else:
            print("Blockchain not connected. Unable to sync database.")
            return False
    except Exception as e:
        print(f"Error with web3 connection: {e}")
        return False

@admin_required
def admin_dashboard(request):
    """Admin dashboard showing voting pools and statistics."""
    # Import necessary utility functions
    from .utils.contract_utils import get_web3, get_voting_contract, get_admin_contract, get_pool_count
    from .utils.contract_utils import get_voting_contract_address, get_admin_contract_address
    from .utils.blockchain_monitor import BlockchainMonitor
    import datetime
    
    # Initialize default values
    active_pools = []
    active_pools_count = 0
    total_votes = 0
    blockchain_connected = False
    node_status = "Not connected"
    chain_id = "Unknown"
    voting_contract_address = get_voting_contract_address()
    admin_contract_address = get_admin_contract_address()
    blockchain_reset = False
    
    # Try to get data from the blockchain
    try:
        web3 = get_web3()
        
        if web3.is_connected():
            blockchain_connected = True
            
            # Check for blockchain reset
            reset_detected, deleted_count = BlockchainMonitor.process_blockchain_connection(web3)
            if reset_detected:
                blockchain_reset = True
                messages.warning(request, f"Blockchain reset detected. All old candidates ({deleted_count}) have been removed.")
            
            try:
                # Get chain ID and block number for status display
                chain_id = web3.eth.chain_id
                block_number = web3.eth.block_number
                node_status = f"Connected (Chain ID: {chain_id}, Block: {block_number})"
                
                # Get contract and count of pools
                voting_contract = get_voting_contract()
                pool_count = get_pool_count()
                
                # Sync database with blockchain
                sync_database_with_blockchain()
                
                # Fetch pool details for all pools
                for pool_id in range(pool_count):
                    try:
                        # Get pool details
                        pool_details = voting_contract.functions.getPoolDetails(pool_id).call()
                        id, category, candidates, start_time, end_time, status = pool_details
                        
                        # Get total votes for this pool
                        pool_votes = 0
                        candidate_votes = []
                        
                        for candidate_name in candidates:
                            try:
                                votes = voting_contract.functions.getVotes(pool_id, candidate_name).call()
                                pool_votes += votes
                                candidate_votes.append({'name': candidate_name, 'votes': votes})
                            except Exception as e:
                                print(f"Error getting votes for {candidate_name}: {e}")
                                candidate_votes.append({'name': candidate_name, 'votes': 0})
                        
                        # Convert timestamps to readable dates
                        try:
                            start_date = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d')
                            end_date = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d')
                        except:
                            start_date = 'N/A'
                            end_date = 'N/A'
                        
                        # Convert numeric status to text
                        # PoolStatus: 0=Pending, 1=Active, 2=Cancelled, 3=Ended
                        status_text = ["Pending", "Active", "Cancelled", "Ended"][status] if status < 4 else "Unknown"
                        
                        # Check if the pool is actually active based on timestamps
                        current_time = datetime.datetime.now().timestamp()
                        is_time_active = start_time <= current_time <= end_time
                        
                        # If status is "Pending" but time is within range, update status to "Active"
                        if status == 0 and is_time_active:
                            status_text = "Active"
                            # Only count as active if time is within range
                            active_pools_count += 1
                        # If status is already "Active", count it
                        elif status == 1:
                            active_pools_count += 1
                            
                        # Add to active pools list for display
                        active_pools.append({
                            'id': id,
                            'category': category,
                            'start_time': start_date,
                            'end_time': end_date,
                            'votes': pool_votes,
                            'candidates': candidate_votes,
                            'status': status_text
                        })
                        
                        # Add to total votes count
                        total_votes += pool_votes
                                                
                    except Exception as e:
                        print(f"Error getting details for pool {pool_id}: {e}")
                        
            except Exception as e:
                print(f"Error getting contracts: {e}")
        else:
            # If web3 is not connected, log the issue
            print(f"⚠️ Web3 is not connected to node at {web3.provider}")
    except Exception as e:
        print(f"⚠️ Error in blockchain connection: {e}")
    
    # Fallback to database candidates if needed
    if not active_pools and blockchain_connected:
        # If blockchain is connected but no pools found, this is 0 pools situation
        messages.info(request, "Blockchain connected, but no voting pools created yet.")
        active_pools_count = 0
    elif not active_pools:
        messages.warning(request, "No blockchain data found. Using database data instead.")
        # Get candidates from the database as fallback
        categories = Candidate.objects.values_list('category', flat=True).distinct()
        
        for category in categories:
            candidates = Candidate.objects.filter(category=category)
            category_votes = sum(c.votes for c in candidates)
            total_votes += category_votes
            
            candidate_votes = [{'name': c.name, 'votes': c.votes} for c in candidates]
            
            active_pools.append({
                'id': 0,  # Placeholder ID since not from blockchain
                'category': category,
                'start_time': 'N/A',
                'end_time': 'N/A',
                'votes': category_votes,
                'candidates': candidate_votes,
                'status': 'Active'
            })
        
        active_pools_count = len(active_pools)

    # Get admin users from the database
    admin_users = CustomUser.objects.filter(user_type='admin')
    admin_list = []
    
    for admin in admin_users:
        # Avoid using wallet_address until migration is applied
        admin_list.append({
            'id': admin.id,
            'username': admin.username,
            'email': admin.email,
            'wallet_address': None,  # Set to None until migration is applied
            'is_active': admin.is_active
        })
    
    # Get pending proposals (placeholder for now - will be implemented with smart contract)
    # In a real implementation, fetch proposals from the contract
    pending_proposals = 0
    pending_requests = []
    
    context = {
        'active_tab': 'dashboard',
        'active_pools_count': active_pools_count,
        'total_votes': total_votes,
        'pending_proposals': pending_proposals,
        'active_pools': active_pools,
        'pending_requests': pending_requests,
        'admin_list': admin_list,
        # Blockchain info for debugging
        'node_status': node_status,
        'voting_contract_address': voting_contract_address,
        'admin_contract_address': admin_contract_address,
        'chain_id': chain_id,
        'blockchain_connected': blockchain_connected
    }
    
    return render(request, "voting/admin_dashboard.html", context)

@admin_required
def admin_create_pool(request):
    """Form to create a new voting pool."""
    import datetime
    from .utils.contract_utils import get_web3, get_voting_contract_address
    
    if request.method == 'POST':
        try:
            # Check if user has connected a wallet
            if not request.user.wallet_address:
                messages.error(request, "You must connect your blockchain wallet first. Please go to 'Connect Wallet' page.")
                return redirect('wallet_connect')
                
            # Get form data
            category = request.POST.get('category')
            description = request.POST.get('description')
            min_admins = int(request.POST.get('min_admins', 3))
            
            # Get candidate data
            candidate_names = request.POST.getlist('candidate_name[]')
            candidate_descriptions = request.POST.getlist('candidate_description[]')
            
            # Validate data
            if not category:
                messages.error(request, "Please provide a category name")
                return redirect('admin_create_pool')
            
            if len(candidate_names) < 2:
                messages.error(request, "At least two candidates are required")
                return redirect('admin_create_pool')
            
            # Set default dates (start now, end in 5 days)
            now = datetime.datetime.now()
            
            # Start time - add 5 minutes to allow for transaction confirmation
            start_dt = now + datetime.timedelta(minutes=2)  
            start_dt = start_dt.replace(second=0, microsecond=0)
            
            # End time - 5 days from now
            end_dt = now + datetime.timedelta(days=5)
            end_dt = end_dt.replace(hour=23, minute=59, second=59, microsecond=0)
            
            # Convert to timestamps
            start_timestamp = int(start_dt.timestamp())
            end_timestamp = int(end_dt.timestamp())
            
            # Use connected wallet via Web3 instead of private key
            web3 = get_web3()
            
            if not web3.is_connected():
                messages.error(request, "Cannot connect to blockchain. Make sure the blockchain server is running.")
                return redirect('admin_create_pool')
            
            # Convert to checksum address for blockchain
            admin_address = web3.to_checksum_address(request.user.wallet_address)
            
            # Call smart contract directly with user's account
            # Note: This requires MetaMask and will show a signing prompt for the user
            messages.success(request, "Transaction prepared. MetaMask will prompt you to sign the transaction.")
            
            # Create candidate records in database
            for i, name in enumerate(candidate_names):
                description = candidate_descriptions[i] if i < len(candidate_descriptions) else ""
                # Check if candidate already exists
                existing = Candidate.objects.filter(name=name, category=category).first()
                if not existing:
                    # Create new candidate in database
                    Candidate.objects.create(
                        name=name,
                        description=description,
                        category=category,
                        votes=0  # Start with zero votes
                    )
            
            context = {
                'active_tab': 'create_pool',
                'category': category,
                'candidates': candidate_names,
                'start_timestamp': start_timestamp,
                'end_timestamp': end_timestamp,
                'admin_address': admin_address,
                'description': description,
                'voting_contract_address': get_voting_contract_address(),
                'show_confirmation': True
            }
            return render(request, "voting/admin_create_pool_confirm.html", context)
            
        except Exception as e:
            messages.error(request, f"Error creating voting pool: {str(e)}")
            return redirect('admin_create_pool')
    
    context = {
        'active_tab': 'create_pool'
    }
    return render(request, "voting/admin_create_pool.html", context)

@admin_required
def admin_cancel_pool_list(request):
    """List of all voting pools that can be cancelled."""
    # Import necessary utility functions
    from .utils.contract_utils import get_web3, get_voting_contract, get_pool_count
    import datetime
    
    # Initialize default values
    active_pools = []
    
    # Get web3 connection and contract
    try:
        web3 = get_web3()
        
        if web3.is_connected():
            try:
                # Get contract and count of pools
                voting_contract = get_voting_contract()
                pool_count = get_pool_count()
                
                # Fetch pool details for all pools
                for pool_id in range(pool_count):
                    try:
                        # Get pool details
                        pool_details = voting_contract.functions.getPoolDetails(pool_id).call()
                        id, category, candidates, start_time, end_time, status = pool_details
                        
                        # Convert timestamps to readable dates
                        start_date = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d')
                        end_date = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d')
                        
                        # Status 1 means Active - only show active pools for cancellation
                        if status == 1:  # Active pools only
                            active_pools.append({
                                'id': id,
                                'category': category,
                                'start_time': start_date,
                                'end_time': end_date
                            })
                    except Exception as e:
                        print(f"Error getting details for pool {pool_id}: {e}")
            except Exception as e:
                print(f"Error connecting to contract: {e}")
        else:
            messages.warning(request, "Blockchain not connected. Unable to retrieve real pool data.")
    except Exception as e:
        print(f"Error with web3 connection: {e}")
    
    # If no active pools found in blockchain, use placeholder data
    if not active_pools:
        # Get data from database as fallback
        categories = Candidate.objects.values_list('category', flat=True).distinct()
        
        for i, category in enumerate(categories):
            active_pools.append({
                'id': i,
                'category': category,
                'start_time': 'N/A',
                'end_time': 'N/A'
            })
    
    context = {
        'active_tab': 'cancel_pool',
        'active_pools': active_pools
    }
    return render(request, "voting/admin_cancel_pool.html", context)

@admin_required
def admin_cancel_pool(request, pool_id):
    """Interface to request cancellation of a specific voting pool."""
    # Get details for the specific pool being cancelled
    from .utils.contract_utils import get_pool_details
    import datetime
    
    # Try to get pool details from blockchain
    try:
        pool_details = get_pool_details(pool_id)
        id, category, candidates, start_time, end_time, status = pool_details
        
        # Convert timestamps to readable dates
        start_date = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d')
        end_date = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d')
        
        pool = {
            'id': id,
            'category': category,
            'start_time': start_date,
            'end_time': end_date,
            'status': ["Pending", "Active", "Cancelled", "Ended"][status] if status < 4 else "Unknown"
        }
        
        # Only show the target pool
        active_pools = [pool]
        
    except Exception as e:
        # If blockchain access fails, use a fallback for the view
        messages.warning(request, f"Could not retrieve blockchain data: {e}")
        # Sample data for display
        active_pools = [
            {'id': pool_id, 'category': 'Unknown Pool', 'start_time': 'N/A', 'end_time': 'N/A'}
        ]
    
    context = {
        'active_tab': 'cancel_pool',
        'active_pools': active_pools,
        'pool_id': pool_id
    }
    return render(request, "voting/admin_cancel_pool.html", context)

@admin_required
def admin_replace_admin(request):
    """Interface to request admin replacement."""
    # Placeholder data
    context = {
        'active_tab': 'replace_admin',
        'admins': [
            {'id': 1, 'username': 'Admin 1', 'email': 'admin1@example.com', 'wallet_address': '0x1234567890abcdef1234567890abcdef12345678'},
            {'id': 2, 'username': 'Admin 2', 'email': 'admin2@example.com', 'wallet_address': '0xabcdef1234567890abcdef1234567890abcdef12'},
        ],
        'candidates': [
            {'id': 1, 'username': 'User 1', 'email': 'user1@example.com'},
            {'id': 2, 'username': 'User 2', 'email': 'user2@example.com'},
        ]
    }
    return render(request, "voting/admin_replace_admin.html", context)

@admin_required
def admin_proposals(request):
    """Page to review and approve/reject proposals."""
    # Placeholder data
    context = {
        'active_tab': 'proposals',
        'proposals': [
            {
                'id': 1, 
                'type': 'Cancel Pool', 
                'requester': 'admin@example.com',
                'created_at': '2025-05-28',
                'details': 'Request to cancel President voting pool due to technical issues.'
            },
        ]
    }
    return render(request, "voting/admin_proposals.html", context)

@admin_required
def wallet_connect(request):
    """Page to connect blockchain wallet."""
    context = {
        'active_tab': 'wallet',
    }
    return render(request, "voting/wallet_connect.html", context)

@admin_required
def admin_view_pool(request, pool_id):
    """View details of a specific voting pool with real blockchain data."""
    from .utils.contract_utils import get_contract, get_pool_details
    import datetime
    
    try:
        # Get pool details from the blockchain
        contract = get_contract()
        pool_details = get_pool_details(pool_id)
        id, category, candidates, start_time, end_time, status = pool_details
        
        # Convert timestamps to readable dates
        start_date = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d')
        end_date = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d')
        
        # Check if the pool is actually active based on timestamps
        current_time = datetime.datetime.now().timestamp()
        is_time_active = start_time <= current_time <= end_time
        
        # Determine status text based on blockchain status and time
        if status == 0 and is_time_active:  # Pending but within time range
            status_text = "Active"
        else:
            # PoolStatus: 0=Pending, 1=Active, 2=Cancelled, 3=Ended
            status_text = ["Pending", "Active", "Cancelled", "Ended"][status] if status < 4 else "Unknown"
        
        # Get votes for each candidate
        candidate_votes = []
        total_votes = 0
        
        for candidate in candidates:
            votes = contract.functions.getVotes(pool_id, candidate).call()
            total_votes += votes
            candidate_votes.append({
                'name': candidate,
                'votes': votes
            })
        
        pool = {
            'id': id,
            'category': category,
            'start_time': start_date,
            'end_time': end_date,
            'votes': total_votes,
            'candidates': candidate_votes,
            'status': status_text
        }
        
    except Exception as e:
        # If blockchain data retrieval fails, fall back to database
        messages.error(request, f"Error retrieving blockchain data: {e}")
        print(f"Blockchain data retrieval error: {e}")
        
        # Fallback to database - create mock pool data based on database
        try:
            # Try to use database categories (in case pool_id maps to category index)
            categories = list(Candidate.objects.values_list('category', flat=True).distinct())
            category = categories[pool_id] if pool_id < len(categories) else "Unknown"
        except:
            category = "Unknown"
            
        # Get candidates for this category
        candidates = Candidate.objects.filter(category=category)
        total_votes = sum(c.votes for c in candidates)
        
        candidate_votes = [{'name': c.name, 'votes': c.votes} for c in candidates]
        
        pool = {
            'id': pool_id,
            'category': category,
            'start_time': 'N/A',
            'end_time': 'N/A',
            'votes': total_votes,
            'candidates': candidate_votes
        }
    
    context = {
        'active_tab': 'dashboard',
        'pool': pool
    }
    
    return render(request, "voting/admin_view_pool.html", context)

@admin_required
def admin_view_proposal(request, proposal_id):
    """View details of a specific proposal."""
    # Placeholder data
    proposal = {
        'id': proposal_id,
        'type': 'Cancel Pool',
        'requester': 'admin@example.com',
        'created_at': '2025-05-28',
        'details': 'Request to cancel President voting pool due to technical issues.',
        'status': 'Pending'
    }
    context = {
        'active_tab': 'proposals',
        'proposal': proposal
    }
    return render(request, "voting/admin_view_proposal.html", context)

# Admin API endpoints (These would be AJAX endpoints in a real implementation)
@admin_required
def admin_submit_cancel_request(request):
    """API endpoint to submit a cancel request."""
    if request.method == 'POST':
        # Get the pool ID from the form
        pool_id = request.POST.get('pool_id')
        reason = request.POST.get('reason')
        
        # Process the cancel request
        messages.success(request, f"✅ Cancel request for pool #{pool_id} submitted successfully. Reason: {reason}")
    return redirect('admin_dashboard')

@admin_required
def admin_submit_replace_request(request):
    """API endpoint to submit an admin replacement request."""
    if request.method == 'POST':
        # Process the replacement request
        messages.success(request, "✅ Replacement request submitted successfully.")
    return redirect('admin_replace_admin')

@admin_required
def admin_approve_proposal(request):
    """API endpoint to approve a proposal."""
    if request.method == 'POST':
        # Process the approval
        messages.success(request, "✅ Proposal approved successfully.")
    return redirect('admin_proposals')

@admin_required
def admin_reject_proposal(request):
    """API endpoint to reject a proposal."""
    if request.method == 'POST':
        # Process the rejection
        messages.success(request, "✅ Proposal rejected successfully.")
    return redirect('admin_proposals')


