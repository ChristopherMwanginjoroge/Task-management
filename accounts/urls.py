from django.urls import path,re_path

from .views import (
    
    OtpVerificationView,
    OtpResendView,
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    CustomTokenVerifyView,
    CustomProviderAuthView,
    login_user,
    home,
    landing,
    Register_user
)

urlpatterns=[
    re_path(r'^auth/(?P<provider>\w+)/$', CustomProviderAuthView.as_view(), name='provider-auth'),

    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', CustomTokenVerifyView.as_view(), name='token_verify'),

    path('otp/verify/', OtpVerificationView.as_view(), name='otp_verification'),
    path('otp/resend/', OtpResendView.as_view(), name='otp_resend'),

    path('login/', login_user, name='login_user'),
    path('home/', home, name='home'),
    path('', landing, name='landing'),
    path('register/', Register_user, name='register_user'),


]