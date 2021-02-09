from rest_framework import serializers
# from rest_framework.permissions import IsAuthenticated
# from django.db import models
from django.contrib.auth.models import User
# from django.contrib.auth import authenticate
# from django.contrib.auth.hashers import make_password
# Register serializer
from django.contrib.auth import password_validation


class RegisterSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ('id', 'username', 'email', 'password', 'first_name', 'last_name')
    extra_kwargs = {'password': {'write_only': True}}

  def validate_email(self, emails):
      if User.objects.filter(email=emails).exists():
          raise serializers.ValidationError('email already exist.')
      return emails

  def validate_password(self, value):
      password_validation.validate_password(value, self.instance)
      return value

  def create(self, validated_data):
    user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'], first_name=validated_data['first_name'],  last_name=validated_data['last_name'])

    return user
# User serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# -------------------------------------------------------------------------------------------
# ==================== Reset Password ==========

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from django.contrib.auth.models import User


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=8, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
