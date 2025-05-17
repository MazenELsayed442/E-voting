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
from .models import Candidate, CustomUser, Voter, PoolCancellationRequest
from .utils.contract_utils import get_vote_count, submit_vote, get_web3, get_contract, get_pool_details, get_pool_count, get_voting_contract, get_admin_contract, get_voting_contract_address, get_admin_contract_address, load_abi
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
                        if status == 1 or (status == 0 and start_time <= datetime.datetime.now().timestamp() <= end_time):  # Active or within time range
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
    from .utils.contract_utils import get_web3, get_voting_contract, get_pool_count
    from .utils.contract_utils import get_voting_contract_address, get_admin_contract_address
    import datetime
    
    # Default values for blockchain connection status
    node_status = "Disconnected"
    chain_id = None
    blockchain_connected = False
    
    # Initialize values for UI
    active_pools_count = 0
    total_votes = 0
    active_pools = []
    pending_proposals = 0  # to display in the stats card
    
    # Try to connect to blockchain and get data
    try:
        web3 = get_web3()
        
        if web3.is_connected():
            node_status = "Connected"
            blockchain_connected = True
            chain_id = web3.eth.chain_id
            
            try:
                # Get voting contract and pool count
                voting_contract = get_voting_contract()
                pool_count = get_pool_count()
                
                # Iterate through pools to get data
                for pool_id in range(pool_count):
                    try:
                        # Get pool details from contract
                        pool_details = voting_contract.functions.getPoolDetails(pool_id).call()
                        id, category, candidates, start_time, end_time, status = pool_details
                        
                        # Process timestamps
                        start_date = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d')
                        end_date = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d')
                        
                        pool_status_text = ["Pending", "Active", "Cancelled", "Ended"][status] if status < 4 else "Unknown"
                        
                        # Check if pool is within its time window
                        now = datetime.datetime.now().timestamp()
                        is_active_time = start_time <= now <= end_time
                        
                        # Consider time-based activity too
                        if (status == 1) or (status == 0 and is_active_time):
                            active_pools_count += 1
                                
                        # Get vote counts for this pool
                        pool_votes = 0
                        for candidate in candidates:
                            try:
                                votes = voting_contract.functions.getVotes(pool_id, candidate).call()
                                pool_votes += votes
                            except Exception as e:
                                print(f"Error getting votes for {candidate} in pool {pool_id}: {e}")
                        
                        total_votes += pool_votes
                        
                        # Add to active pools list for display
                        # Include all pools regardless of status for the table
                        active_pools.append({
                            'id': id,
                            'category': category,
                            'candidates': len(candidates),
                            'votes': pool_votes,
                            'start_date': start_date,
                            'end_date': end_date,
                            'status': pool_status_text,
                            'is_active': (status == 1) or (status == 0 and is_active_time)
                        })
                            
                    except Exception as e:
                        print(f"Error getting details for pool {pool_id}: {e}")
                
            except Exception as e:
                print(f"Error getting contract data: {e}")
                
    except Exception as e:
        print(f"Blockchain connection error: {e}")
    
    # If we couldn't get active pools from blockchain, use a fallback
    if not active_pools:
        # Get categories from database
        categories = Candidate.objects.values_list('category', flat=True).distinct()
        
        # Create placeholder pools for display
        for i, category in enumerate(categories):
            candidates_count = Candidate.objects.filter(category=category).count()
            
            # Get vote count from database
            vote_count = sum(c.votes for c in Candidate.objects.filter(category=category))
            
            active_pools.append({
                'id': i,
                'category': category,
                'candidates': candidates_count,
                'votes': vote_count,
                'start_date': 'N/A',
                'end_date': 'N/A',
                'status': 'Active',
                'is_active': True
            })
        
        active_pools_count = len(active_pools)
        total_votes = sum(pool['votes'] for pool in active_pools)
    
    # Sort active pools by ID
    active_pools = sorted(active_pools, key=lambda x: x['id'])
    
    # Get contract addresses
    voting_contract_address = get_voting_contract_address()
    admin_contract_address = get_admin_contract_address()
    
    # Get admin users from the database
    admin_users = CustomUser.objects.filter(user_type='admin')
    admin_list = []
    
    for admin in admin_users:
        admin_list.append({
            'id': admin.id,
            'username': admin.username,
            'email': admin.email,
            'wallet_address': admin.wallet_address,
            'is_active': admin.is_active
        })
    
    # Get pending cancellation requests
    pending_cancellation_requests = PoolCancellationRequest.objects.filter(status='pending')
    pending_proposals = pending_cancellation_requests.count()
    
    # Prepare proposals for the UI
    pending_requests = []
    for req in pending_cancellation_requests:
        pending_requests.append({
            'id': req.id,
            'type': 'Cancel Pool',
            'proposer': req.initiator.username,
            'approvals': '1/2',  # Always 1/2 since it's waiting for a second approval
            'pool_id': req.pool_id
        })
    
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
            
            # Get candidate data
            candidate_names = request.POST.getlist('candidate_name[]')
            candidate_descriptions = request.POST.getlist('candidate_description[]')
            
            # Get datetime fields
            start_datetime_str = request.POST.get('start_datetime')
            end_datetime_str = request.POST.get('end_datetime')
            
            # Validate data
            if not category:
                messages.error(request, "Please provide a category name")
                return redirect('admin_create_pool')
            
            if len(candidate_names) < 2:
                messages.error(request, "At least two candidates are required")
                return redirect('admin_create_pool')
                
            if not start_datetime_str or not end_datetime_str:
                messages.error(request, "Start and end dates are required")
                return redirect('admin_create_pool')
            
            # Parse datetime strings to datetime objects
            try:
                start_dt = datetime.datetime.fromisoformat(start_datetime_str)
                end_dt = datetime.datetime.fromisoformat(end_datetime_str)
                
                # Ensure end time is after start time
                if end_dt <= start_dt:
                    messages.error(request, "End time must be after start time")
                    return redirect('admin_create_pool')
                
                # Ensure minimum voting period (1 hour)
                min_duration = datetime.timedelta(hours=1)
                if end_dt - start_dt < min_duration:
                    messages.error(request, "Voting period must be at least 1 hour")
                    return redirect('admin_create_pool')
                
                # Convert to timestamps
                start_timestamp = int(start_dt.timestamp())
                end_timestamp = int(end_dt.timestamp())
                
                # Ensure start time is in the future
                now = datetime.datetime.now()
                if start_dt < now:
                    messages.error(request, "Start time must be in the future")
                    return redirect('admin_create_pool')
                
            except ValueError:
                messages.error(request, "Invalid date format")
                return redirect('admin_create_pool')
            
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
                        if status == 1 or (status == 0 and start_time <= datetime.datetime.now().timestamp() <= end_time):  # Active or within time range pools only
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
        # Get the pool ID and reason from the form
        pool_id = request.POST.get('pool_id')
        reason = request.POST.get('reason')
        
        if not pool_id or not reason:
            messages.error(request, "❌ Pool ID and reason are required.")
            return redirect('admin_cancel_pool')
        
        try:
            # Create a new pool cancellation request
            cancellation_request = PoolCancellationRequest.objects.create(
                pool_id=int(pool_id),
                reason=reason,
                initiator=request.user,
                status='pending'
            )
            
            messages.success(request, f"✅ Cancel request for pool #{pool_id} submitted successfully. Waiting for another admin to approve.")
            return redirect('admin_pending_cancellations')
        except Exception as e:
            messages.error(request, f"❌ Failed to create cancellation request: {str(e)}")
            return redirect('admin_cancel_pool')
    
    return redirect('admin_dashboard')

@admin_required
def admin_pending_cancellations(request):
    """View to list all pending cancellation requests."""
    # Get all pending cancellation requests
    pending_requests = PoolCancellationRequest.objects.filter(status='pending')
    
    # Get all approved but not executed requests
    approved_requests = PoolCancellationRequest.objects.filter(
        status='approved', 
        transaction_hash__isnull=True
    )
    
    # Get recently executed requests (limit to 5)
    executed_requests = PoolCancellationRequest.objects.filter(
        status='executed'
    ).order_by('-updated_at')[:5]
    
    # Get contract address and ABI for the frontend
    from .utils.contract_utils import get_admin_contract_address, load_abi
    admin_contract_address = get_admin_contract_address()
    admin_contract_abi = load_abi("artifacts/contracts/VotingAdmin.sol/VotingAdmin.json")
    
    context = {
        'active_tab': 'pending_cancellations',
        'pending_requests': pending_requests,
        'approved_requests': approved_requests,
        'executed_requests': executed_requests,
        'admin_contract_address': admin_contract_address,
        'admin_contract_abi': json.dumps(admin_contract_abi)
    }
    
    return render(request, 'voting/admin_pending_cancellations.html', context)

@admin_required
def admin_approve_cancellation(request, request_id):
    """View to approve a cancellation request."""
    if request.method == 'POST':
        try:
            cancellation_request = PoolCancellationRequest.objects.get(id=request_id)
            
            # Check if the request is still pending
            if cancellation_request.status != 'pending':
                messages.error(request, "❌ This request has already been processed.")
                return redirect('admin_pending_cancellations')
            
            # Check if the approver is not the same as the initiator
            if cancellation_request.initiator == request.user:
                messages.error(request, "❌ You cannot approve your own cancellation request.")
                return redirect('admin_pending_cancellations')
            
            # Update the request status and approver
            cancellation_request.status = 'approved'
            cancellation_request.approver = request.user
            cancellation_request.save()
            
            # Now execute the cancellation on the blockchain
            try:
                from .utils.contract_utils import get_web3, get_voting_contract, get_admin_contract
                
                web3 = get_web3()
                
                if not web3.is_connected():
                    messages.warning(request, "⚠️ Could not connect to blockchain. The cancellation is approved but not executed.")
                    return redirect('admin_pending_cancellations')
                
                admin_contract = get_admin_contract()
                
                # Get the wallet address of the current admin (approver)
                admin_address = web3.to_checksum_address(request.user.wallet_address)
                
                # Call the smart contract function to cancel the pool
                tx = admin_contract.functions.cancelPool(
                    cancellation_request.pool_id
                ).build_transaction({
                    'from': admin_address,
                    'nonce': web3.eth.get_transaction_count(admin_address),
                    'gas': 1000000,
                    'gasPrice': web3.eth.gas_price
                })
                
                # At this point, we would normally sign the transaction with the admin's private key
                # but in a web context, we'd use MetaMask for this
                # So we'll mark it as approved and provide instructions to the admin
                
                messages.success(request, f"✅ Cancellation request approved. Please use MetaMask to sign the transaction to execute the cancellation.")
                
                # For demonstration only, in real implementation this would be handled via MetaMask
                # If we had the admin's private key:
                # signed_tx = web3.eth.account.sign_transaction(tx, private_key)
                # tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                # cancellation_request.transaction_hash = tx_hash.hex()
                # cancellation_request.status = 'executed'
                # cancellation_request.save()
                
                return redirect('admin_pending_cancellations')
                
            except Exception as e:
                messages.error(request, f"❌ Error executing cancellation on blockchain: {str(e)}")
                return redirect('admin_pending_cancellations')
            
        except PoolCancellationRequest.DoesNotExist:
            messages.error(request, "❌ Cancellation request not found.")
            return redirect('admin_pending_cancellations')
    
    return redirect('admin_pending_cancellations')

@admin_required
def admin_reject_cancellation(request, request_id):
    """View to reject a cancellation request."""
    if request.method == 'POST':
        try:
            cancellation_request = PoolCancellationRequest.objects.get(id=request_id)
            
            # Check if the request is still pending
            if cancellation_request.status != 'pending':
                messages.error(request, "❌ This request has already been processed.")
                return redirect('admin_pending_cancellations')
            
            # Update the request status and approver
            cancellation_request.status = 'rejected'
            cancellation_request.approver = request.user
            cancellation_request.save()
            
            messages.success(request, "✅ Cancellation request rejected successfully.")
            
        except PoolCancellationRequest.DoesNotExist:
            messages.error(request, "❌ Cancellation request not found.")
    
    return redirect('admin_pending_cancellations')

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

@csrf_exempt
@admin_required
def update_transaction_hash(request, request_id):
    """View to update the transaction hash after it's executed on the blockchain."""
    if request.method == 'POST':
        try:
            # Get the cancellation request
            cancellation_request = get_object_or_404(PoolCancellationRequest, id=request_id)
            
            # Get the transaction hash from request body
            data = json.loads(request.body)
            tx_hash = data.get('transaction_hash')
            
            if not tx_hash:
                return JsonResponse({'success': False, 'error': 'No transaction hash provided'}, status=400)
            
            # Update the cancellation request
            cancellation_request.transaction_hash = tx_hash
            cancellation_request.status = 'executed'
            cancellation_request.save()
            
            return JsonResponse({'success': True, 'message': 'Transaction hash updated successfully'})
            
        except PoolCancellationRequest.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Cancellation request not found'}, status=404)
        
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'}, status=405)


