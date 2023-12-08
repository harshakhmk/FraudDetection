# fraud_api/serializers.py

from rest_framework import serializers
from .models import Transaction, Alert, Document,User
from rest_framework.exceptions import AuthenticationFailed
from django.contrib import auth

# from django.contrib.auth.token import PasswordResetTokenGenerator
from django.utils.encoding import (
    force_str,
    smart_str,
    smart_bytes,
    DjangoUnicodeDecodeError,
)
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from utils.email import Util
from django.urls import reverse




class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=60, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ["email", "username", "password"]

    # This function runs when is_valid() is invoked
    def validate(self, attrs):
        username = attrs.get("username", "")
        email = attrs.get("email", "")

        if not username.isalnum():
            raise ValidationError(
                "user name must contain alpha numeric characters only"
            )

        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=500)

    class Meta:
        model = User
        fields = "token"


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=100, min_length=10)
    password = serializers.CharField(max_length=100, min_length=8, write_only=True)
    username = serializers.CharField(max_length=100, min_length=5, read_only=True)
    tokens = serializers.CharField(max_length=500, read_only=True)

    class Meta:
        model = User
        fields = ("email", "password", "username", "tokens")

    def validate(self, attrs):
        email = attrs.get("email", "")
        password = attrs.get("password", "")

        user = auth.authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed("Invalid Creds")
        if user.is_verified == False:
            AuthenticationFailed("Email not verified")
        return {
            "email": user.email,
            "username": user.username,
            "tokens": user.tokens(),
        }


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=5, max_length=100)

    class Meta:
        fields = ("email",)

    """
    def validate(self,attrs):
        try:
            email = attrs['data'].get("email", "")
            # This user exists
            if User.objects.filter(email=email).exists():
                user = User.objects.filter(email=email)
                uidb64 = urlsafe_base64_encode(user.id)

                # This class will identify user has changed password and then make token invalid
                token  = PasswordResetTokenGenerator.make_token(user)
                current_domain = get_current_site(request = attrs['data'].get('request')).domain
                relative_url = reverse("verify-email")
                absolute_url = 'http://'+current_domain+relative_url+"?token="+str(token)
                message_body = (
                    f"Hi {user.username}, please verify your email address from below link\n"
                    + absolute_url)

                email_data = {
                    "body": message_body,
                    "subject": "Verify your email",
                    "to_email": user.email,
                }
                Util.send_email(email_data)
            else:
                # unknown email
    """

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = '__all__'

class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'

class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = '__all__'
