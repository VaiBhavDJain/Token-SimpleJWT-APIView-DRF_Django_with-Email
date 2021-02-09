# from django.conf.urls import url
from rest_framework_simplejwt import views as jwt_views
from django.contrib import admin
from django.urls import path, include
# from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('user/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('user/', include('User.urls')),
    # url('', include('django.contrib.auth.urls')),
    # url('^password_reset/', auth_views.password_reset),
]
