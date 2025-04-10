from django.contrib import admin
from django.urls import path, include  # استيراد path و include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("voting.urls")),  # ربط تطبيق التصويت
]
