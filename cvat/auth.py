import logging
import os
import requests
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

logger = logging.getLogger(__name__)

class KeycloakJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication for Keycloak-issued tokens.
    Decodes the JWT using Keycloak's public key from the JWKS endpoint.
    """

    def __init__(self):
        super().__init__()
        self._public_key_cache = None
        self._cached_keys = {}

    def get_keycloak_public_key(self):
        """
        Fetch or use cached Keycloak public key.
        First tries to fetch from JWKS endpoint, then tries environment variable.
        """
        # Try to fetch from JWKS endpoint first (preferred method)
        jwks_uri = os.getenv("KEYCLOAK_JWKS_URI") or os.getenv("SOCIAL_AUTH_KEYCLOAK_KEY_URL")
        if jwks_uri:
            try:
                response = requests.get(jwks_uri, timeout=5)
                response.raise_for_status()
                jwks = response.json()
                # Cache the keys by kid
                for key in jwks.get("keys", []):
                    kid = key.get("kid")
                    if kid:
                        self._cached_keys[kid] = key
                logger.debug(f"Fetched JWKS from {jwks_uri}")
                return None  # We'll use the cached keys dict
            except Exception as e:
                logger.warning(f"Failed to fetch JWKS from {jwks_uri}: {e}")
        
        # Fall back to environment variable
        public_key = os.getenv("SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY", "").strip()
        if public_key:
            # Add PEM headers if they're missing
            if not public_key.startswith("-----BEGIN"):
                public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
            return public_key

        return None

    def authenticate(self, request):
        """
        Authenticate the request using Keycloak JWT token.
        """
        auth = get_authorization_header(request).split()

        if not auth:
            return None

        # Check if the authorization type is 'Bearer'
        if auth[0].lower() != b'bearer':
            return None

        if len(auth) == 1:
            msg = "Invalid token header. No credentials provided."
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = "Invalid token header. Token string should not contain spaces."
            raise AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = "Invalid token header. Token string should not contain invalid characters."
            raise AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token):
        """
        Validate the token and return the user.
        """
        try:
            # First, decode without verification to get the header
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
        except jwt.InvalidTokenError as e:
            raise AuthenticationFailed(f"Invalid token format: {e}")

        # Get the public key
        public_key = self.get_keycloak_public_key()

        # Determine which key to use
        payload = None
        try:
            if public_key:
                # Use the public key from environment
                # Skip audience validation for Keycloak tokens
                payload = jwt.decode(token, public_key, algorithms=["RS256"], audience=None, options={"verify_aud": False})
            elif self._cached_keys and kid:
                # Use a key from JWKS cache
                key_data = self._cached_keys.get(kid)
                if key_data:
                    # Convert JWK to PEM format
                    from cryptography.hazmat.primitives.serialization import load_pem_public_key
                    from jwt.algorithms import RSAAlgorithm
                    try:
                        public_key = RSAAlgorithm.from_jwk(key_data)
                        # Skip audience validation for Keycloak tokens
                        payload = jwt.decode(token, public_key, algorithms=["RS256"], audience=None, options={"verify_aud": False})
                    except Exception as e:
                        raise AuthenticationFailed(f"Failed to load key from JWKS: {e}")
                else:
                    raise AuthenticationFailed(f"Key ID {kid} not found in JWKS")
            else:
                raise AuthenticationFailed("No public key available for token validation")
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT validation failed: {e}")
            raise AuthenticationFailed(f"Invalid token: {e}")

        if not payload:
            raise AuthenticationFailed("Failed to decode token")

        logger.debug(f"Token payload: {payload}")

        # Extract user ID from various possible claims
        user_id = payload.get("sub") or payload.get("preferred_username")
        email = payload.get("email")
        preferred_username = payload.get("preferred_username")
        
        if not user_id:
            raise AuthenticationFailed("Token contained no recognizable user identification")

        # Get the user model
        User = get_user_model()
        user = None
        
        # Try to find user by username
        try:
            user = User.objects.get(username=user_id)
            logger.debug(f"Found user by sub/username: {user_id}")
        except User.DoesNotExist:
            # Try by preferred_username
            if preferred_username and preferred_username != user_id:
                try:
                    user = User.objects.get(username=preferred_username)
                    logger.debug(f"Found user by preferred_username: {preferred_username}")
                except User.DoesNotExist:
                    pass
            
            # Try by email
            if not user and email:
                try:
                    user = User.objects.get(email=email)
                    logger.debug(f"Found user by email: {email}")
                except User.DoesNotExist:
                    pass
        
        # If user doesn't exist, create it
        if not user:
            logger.info(f"Creating new user from Keycloak token: {preferred_username or user_id}")
            try:
                user = User.objects.create_user(
                    username=preferred_username or user_id,
                    email=email or "",
                    first_name=payload.get("given_name", ""),
                    last_name=payload.get("family_name", ""),
                )
                logger.info(f"Successfully created user: {user.username}")
            except Exception as e:
                logger.error(f"Failed to create user: {e}")
                raise AuthenticationFailed(f"User creation failed: {e}")

        # All Keycloak-authed users get CVAT admin rights so projects and cloud
        # storages are shared across all users. The post_save signal picks this
        # up and adds the "admin" group, which OPA checks via privilege == "admin".
        # TODO: replace with org-based roles once permissions are revisited.
        if not (user.is_superuser and user.is_staff):
            user.is_superuser = True
            user.is_staff = True
            user.save()

        if not user.is_active:
            raise AuthenticationFailed("User is inactive")

        logger.debug(f"Authentication successful for user: {user.username}")
        return (user, token)
