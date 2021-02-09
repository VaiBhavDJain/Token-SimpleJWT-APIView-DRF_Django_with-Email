from django.conf.urls import url
from .views import RequestPasswordResetEmail,SetNewPasswordAPIView, PasswordTokenCheckAPI
from django.urls import path, include
from User.views import Registerapi, LoginApI
urlpatterns = [
      path('register/', Registerapi),
      path('login/', LoginApI.as_view()),
      path('request-reset-email/', RequestPasswordResetEmail.as_view(), name="request-reset-email"),
      path('password-reset/<uidb64>/<token>', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
      path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password-reset-complete')
]
