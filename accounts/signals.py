from django.dispatch import receiver
from django.db.models.signals import post_save
from django.contrib.auth import get_user_model
from .models import Otp
from django.utils import timezone
from django.core.mail import send_mail
import random 
import logging
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator

logger = logging.getLogger(__name__)

@receiver(post_save, sender=get_user_model())
def handle_user_creation(sender, instance, created, **kwargs):
    if created:
        logger.debug("User created: %s", instance.email)

        if instance.is_superuser:
            return
        
        otp_code=''.join([str(random.randint(0,9))for _ in range(6)])

        otp_token=Otp.objects.create(
            user=instance,
            otp_code=otp_code,
            expires_at=timezone.now()+timezone.timedelta(minutes=10)
        )

        logger.debug("OTP created for user: %s", instance.email)

        instance.is_active=False
        instance.save()

        uid=urlsafe_base64_encode(str(instance.pk).encode())
        token=default_token_generator.make_token(instance)
        activation_url = f"{settings.EMAIL_FRONTEND_PROTOCOL}://{settings.EMAIL_FRONTEND_DOMAIN}/{settings.ACTIVATION_URL.format(uid=uid, token=token)}"

        context={
            'user': instance,
            'otp_code':otp_code,
            'otp_token':otp_token.token_code,
            'activation_url':activation_url,
            
        }

        subject = "Your OTP and Email Verification"
        message = f"Hi {instance.email},\n\nYour OTP is {otp_code}. It will expire in 5 minutes.\n\n" \
                  f"Use the following OTP token to verify your email: {otp_token.token}\n\n" \
                  f"Alternatively, you can verify your email by clicking the link below:\n{activation_url}\n\nBest,\nTeam"
        

        try:
            send_mail(subject, message, settings.EMAIL_HOST_USER, [instance.email])
            logger.debug("Email sent to %s", instance.email)
        except Exception as e:
            logger.error("Error sending email to %s: %s", instance.email, str(e))

        
       


