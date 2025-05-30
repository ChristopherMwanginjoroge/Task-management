from rest_framework import serializers


class OtpVerificationSerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=6)
    otp_token = serializers.CharField(max_length=255)

    def validate_otp_code(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("Invalid OTP code format.")
        return value
    def validate_otp_token(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("Invalid OTP token format.")
        return value
    
class OtpResendSerializer(serializers.Serializer):
    email = serializers.EmailField()


    