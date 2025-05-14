import os
import django
import subprocess
import sys
import time

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eVoting.settings')
django.setup()

# Import the Candidate model and any other relevant models
from voting.models import Candidate
from django.core.cache import cache
from django.db import connection

print("===== إعادة تعيين تطبيق التصويت الإلكتروني =====")
print("1. تنظيف قاعدة البيانات...")

# Clear all candidates
candidate_count = Candidate.objects.all().delete()[0]
print(f"   - تم حذف جميع المرشحين ({candidate_count}) من قاعدة البيانات")

# Clear any cached blockchain data
cache_keys = [
    'last_blockchain_block',
    'active_pools', 
    'pool_categories',
    'blockchain_data'
]
            
for key in cache_keys:
    cache.delete(key)
print("   - تم مسح جميع البيانات المخزنة مؤقتًا")

# Execute raw SQL to ensure tables are completely clean
with connection.cursor() as cursor:
    tables_to_clean = [
        'voting_candidate',  # Main candidate table
    ]
    
    for table in tables_to_clean:
        try:
            cursor.execute(f"DELETE FROM {table}")
            print(f"   - تم تنظيف جدول {table}")
        except Exception as e:
            print(f"   - خطأ في تنظيف جدول {table}: {e}")

print("\n2. إعادة تشغيل خادم التطبيق...")

# Attempt to terminate any existing Django server
try:
    print("   - محاولة إيقاف الخادم الحالي...")
    # Use a different approach for Windows vs Unix
    if os.name == 'nt':  # Windows
        subprocess.run("taskkill /f /im python.exe", shell=True, stderr=subprocess.PIPE)
    else:  # Unix/Mac
        subprocess.run("pkill -f 'python manage.py runserver'", shell=True, stderr=subprocess.PIPE)
    print("   - تم إيقاف الخادم الحالي")
except Exception as e:
    print(f"   - ملاحظة: لم يتم العثور على خادم قيد التشغيل أو لم يمكن إيقافه: {e}")

# Wait a moment for ports to be freed
time.sleep(1)

print("   - بدء تشغيل خادم جديد...")

# Start a new Django server
try:
    # Use a different approach for Windows vs Unix
    if os.name == 'nt':  # Windows
        subprocess.Popen("start cmd /k python manage.py runserver", shell=True)
    else:  # Unix/Mac
        subprocess.Popen("python manage.py runserver &", shell=True)
    print("   - تم بدء تشغيل الخادم بنجاح")
except Exception as e:
    print(f"   - فشل في بدء الخادم: {e}")

print("\n===== اكتملت إعادة تعيين التطبيق =====")
print("يمكنك الآن زيارة التطبيق في المتصفح على العنوان: http://127.0.0.1:8000")
print("ملاحظة: تأكد من أن خادم Hardhat للبلوكتشين قيد التشغيل") 