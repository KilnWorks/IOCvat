from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class KeycloakJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):

        username = validated_token.get("preferred_username")

        if not username:
            raise exceptions.AuthenticationFailed("Token missing 'preferred_username'")

        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": validated_token.get("email", ""),
                "first_name": validated_token.get("given_name", ""),
                "last_name": validated_token.get("family_name", ""),
            }
        )

        return user

    def authenticate(self, request):
        logger.warning("🚪 Entering KeycloakJWTAuthentication.authenticate()")

        user_auth_tuple = super().authenticate(request)

        if user_auth_tuple:
            user, _ = user_auth_tuple
            logger.warning(f"✅ Authenticated API user: {user}")
        else:
            logger.warning("❌ No API authentication")

        return user_auth_tuple