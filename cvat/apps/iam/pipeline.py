import logging
logger = logging.getLogger(__name__)

def assign_backend_to_user(strategy, details, user=None, *args, **kwargs):

    # raise Exception("🚨 assign_backend_to_user CALLED")
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"✅ assign_backend_to_user called. User: {user}")

    if user:
        user.backend = 'social_core.backends.keycloak.KeycloakOAuth2'

def save_id_token(backend, user, response, *args, **kwargs):
    if backend.name == 'keycloak':
        id_token = response.get('id_token')
        if id_token:
            social = user.social_auth.get(provider='keycloak')
            social.extra_data['id_token'] = id_token
            social.save()

# def assign_backend_to_user(backend, user, *args, **kwargs):
#     """
#     Assigns the backend to the user for successful login in Django session.
#     This is required when using multiple authentication backends.
#     """
#     # if user and not hasattr(user, 'backend'):
#         # user.backend = f"{backend.__module__}.{backend.__class__.__name__}"
#         # user.backend = 'social_core.backends.keycloak.KeycloakOAuth2'
#     logger.warning("🧩 assign_backend_to_user CALLED")
#     if user:
#         user.backend = 'social_core.backends.keycloak.KeycloakOAuth2'
#         logger.warning(f"🔑 backend assigned to user {user.username}")

def debug_pipeline_step(strategy, details, user=None, *args, **kwargs):
    logger = logging.getLogger(__name__)
    logger.warning("📍 Reached debug_pipeline_step")

def assign_backend_to_user_dummy(backend, user, *args, **kwargs):
    logger.warning("📍 CALLED")
