from django.shortcuts import render,redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import OtpVerificationSerializer,OtpResendSerializer
from .models import User,Otp
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from djoser.social.views import ProviderAuthView
import random
from rest_framework_simplejwt.views import(
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from django.contrib import messages

from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm



# Create your views here.

class OtpVerificationView(APIView):
    authentication_classes = []
    permission_classes = []
    def post(self, request):
        serializer = OtpVerificationSerializer(data=request.data)
        if serializer.is_valid():
            otp_code = serializer.validated_data['otp_code']
            otp_token = serializer.validated_data['otp_token']

            # fetch the OTP object from the database
            try:
                otp = Otp.objects.get(otp_code=otp_code, token_code=otp_token)
            except Otp.DoesNotExist:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            
            #check if it has expired
            if otp.expires_at < timezone.now():
                return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)
            
            #check if the user is already active
            if otp.user.is_active:
                return Response({'error': 'User is already active'}, status=status.HTTP_400_BAD_REQUEST)
            
            #activate the user
            otp.user.is_active = True
            otp.user.save()

            refresh=RefreshToken.for_user(otp.user)
            access_token=str(refresh.access_token)
            refresh_token=str(refresh)

            response=Response({
                'detail':'User activated successfully',
                'access_token':access_token,
                'refresh_token':refresh_token
            })

            response.set_cookie(
                'access',access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )
            
            response.set_cookie(
                'refresh',refresh_token,
                max_age=settings.AUTH_COOKIE_REFRESH_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )
            return response
        
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class OtpResendView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = OtpResendSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            #check if the user exists
            try:
                user=get_user_model().objects.get(email=email)
            except get_user_model().DoesNotExist:
                return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
            
            #check if the user is already active
            if user.is_active:
                return Response({'error': 'User is already active'}, status=status.HTTP_400_BAD_REQUEST)

            #generate a new OTP

            otp_code=''.join([str(random.randint(0,9))for _ in range(6)])

            otp_token=Otp.objects.create(
                user=user,
                otp_code=otp_code,
                expires_at=timezone.now()+timezone.timedelta(minutes=10)
            )

            #send the OTP to the user's email
            subject = "Your OTP and Email Verification"
            message = f"Hi {user.email},\n\nYour OTP is {otp_code}. It will expire in 5 minutes.\n\n" \
            f"Use the following OTP token to verify your email: {otp_token.token}\n\n" \
            f"If you did not request this, please ignore this email."

            send_mail(
                subject=subject,
                message=message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False
            )
            return Response({'detail': 'OTP sent successfully'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class CustomProviderAuthView(ProviderAuthView):
    def post(self, request, *args,**kwargs):
        response=super().post(request, *args, **kwargs)

        if response.status_code==201:
            access_token=response.data.get('access')
            refresh_token=response.data.get('refresh')

            response.set_cookie(
                'access',access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )
            response.set_cookie(
                'refresh',refresh_token,
                max_age=settings.AUTH_COOKIE_REFRESH_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

        return response
    

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response=super().post(request, *args, **kwargs)

        if response.status_code==200:
            access_token=response.data.get('access')
            refresh_token=response.data.get('refresh')

            response.set_cookie(
                'access',access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )
            response.set_cookie(
                'refresh',refresh_token,
                max_age=settings.AUTH_COOKIE_REFRESH_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

        return response
    
class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token=request.COOKIES.get('refresh')
        if refresh_token:
            request.data['refresh']=refresh_token

        response=super().post(request, *args, **kwargs)

        if response.status_code==200:
            access_token=response.data.get('access')
            refresh_token=response.data.get('refresh')

            response.set_cookie(
                'access',access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )
            response.set_cookie(
                'refresh',refresh_token,
                max_age=settings.AUTH_COOKIE_REFRESH_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )
        return response
    
class CustomTokenVerifyView(TokenVerifyView):
    def post(self, request, *args, **kwargs):
        access_token=request.COOKIES.get('access')
        if access_token:
            request.data['token']=access_token

        response=super().post(request, *args, **kwargs)

        return response
    

def login_user(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid email or password.')
    return render(request, 'login.html')
        
def home(request):
    return render(request,'home.html')

def landing(request):
    return render(request,'landing.html')

def Register_user(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})
        


        


        




