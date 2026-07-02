# IOCvat — Claude Code Configuration

> Auto-loaded by Claude Code on every session in this directory.

---

## What This Project Is

IOCvat is a self-hosted [CVAT](https://github.com/cvat-ai/cvat) instance running in Docker, used as the annotation backend for the IOValence platform. It provides project/task/job management and a web UI for image/video annotation.

- **Web UI**: `iov.iovalence.com` (port 8090 locally via Traefik)
- **API**: `iov.iovalence.com/api/` (used by IOValence hub via Bearer JWT)
- **Docker compose**: `IOCvat/docker-compose.yml`
- **Network**: shares the external `cvat` Docker network with IOHub services

---

## Keycloak Auth Patch

CVAT's built-in Keycloak integration requires a paid subscription. We bypass it with a custom auth layer that validates Keycloak-issued JWTs directly.

### Two code paths — both are patched:

| Path | Trigger | File |
|------|---------|------|
| CVAT web UI login | Keycloak OAuth2 (social auth pipeline) | `cvat/apps/iam/pipeline.py` → `assign_backend_to_user()` |
| IOValence API calls | Bearer JWT in `Authorization` header | `cvat/auth.py` → `KeycloakJWTAuthentication` |

### How JWT auth works (`cvat/auth.py`)

- Extends `JWTAuthentication` from `rest_framework_simplejwt`
- Fetches Keycloak's JWKS from `KEYCLOAK_JWKS_URI` env var (or falls back to `SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY` PEM)
- Validates the RS256 token, extracts `preferred_username` / `email` / `sub`
- Finds the matching Django user by username, email, or Keycloak sub — creates if missing
- Wired into `REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES` in `cvat/settings/base.py`

### Social auth pipeline (`cvat/apps/iam/pipeline.py`)

Custom steps added to `SOCIAL_AUTH_PIPELINE` in `cvat/settings/base.py`:
- `cvat.apps.iam.pipeline.debug_pipeline_step` — logs the pipeline hit
- `cvat.apps.iam.pipeline.save_id_token` — persists Keycloak `id_token` in social auth extra data
- `cvat.apps.iam.pipeline.assign_backend_to_user` — sets `user.backend` + promotes user to admin (see below)

---

## User Permission Workaround (Superuser for All)

**Problem**: CVAT is multi-tenant by default — each user owns their own projects and can't see others'.

**Current fix**: All Keycloak-authed users are promoted to `is_superuser=True, is_staff=True` on login. This causes Django's `post_save` signal (`cvat/apps/iam/signals.py`) to add them to the `"admin"` group, which OPA then reads as `privilege="admin"` → full access to all projects, tasks, and cloud storages.

The promotion runs in **both auth paths**:
- `cvat/auth.py:185` — JWT path: `if not (user.is_superuser and user.is_staff): user.save()`
- `cvat/apps/iam/pipeline.py:17` — social auth path: same guard

**Implication**: every Keycloak user is a full CVAT admin — they can create, edit, and delete any project or task. There is no lower permission tier for Keycloak users right now.

**TODO**: Replace with CVAT Organizations + role tiers (see `IOValence/TODO.md` [IOHub] — "CVAT user permissions — revisit superuser workaround", added 2026-07-02).

---

## ⚠️ Temporary Fix — docker cp

The Docker image build for `cvat_server` uses layer caching aggressively. A `--no-cache` build fails due to pip network issues. Until a clean rebuild strategy is in place, changes to Python source files are applied via `docker cp` directly into the running container:

```bash
docker cp IOCvat/cvat/apps/iam/pipeline.py cvat_server:/home/django/cvat/apps/iam/pipeline.py
docker cp IOCvat/cvat/auth.py cvat_server:/home/django/cvat/auth.py
docker restart cvat_server
```

**Risk**: if the container is deleted and recreated (e.g. `docker compose down` + `up`), these files reset to the old baked image. Re-run the `docker cp` commands above after any full recreation.

The files in `IOCvat/` on disk are always the source of truth — the container just needs to be re-synced.

---

## Rebuild Instructions (Normal)

```bash
cd IOCvat
docker compose build cvat_server          # builds new image (uses cache)
docker compose up -d --force-recreate cvat_server   # replaces running container
# Then re-apply docker cp if cache was used:
docker cp cvat/apps/iam/pipeline.py cvat_server:/home/django/cvat/apps/iam/pipeline.py
docker cp cvat/auth.py cvat_server:/home/django/cvat/auth.py
docker restart cvat_server
```

---

## One-Time User Promotion (new machine or DB reset)

If you need to promote all existing CVAT users to admin (e.g. after a DB restore):

```bash
docker exec cvat_server python manage.py shell -c "
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.conf import settings
User = get_user_model()
admin_group = Group.objects.get(name=settings.IAM_ADMIN_ROLE)
for user in User.objects.filter(is_superuser=False):
    user.is_superuser = True
    user.is_staff = True
    user.save()
    user.groups.add(admin_group)
print('Done.')
"
```

---

## Key Environment Variables (docker-compose.yml)

| Variable | Value / Purpose |
|----------|----------------|
| `KEYCLOAK_JWKS_URI` | `https://auth.iovalence.com/realms/IO-Valence/protocol/openid-connect/certs` |
| `SOCIAL_AUTH_KEYCLOAK_KEY_URL` | `https://auth.iovalence.com/realms/IO-Valence` |
| `SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY` | RS256 public key (PEM without headers) — fallback if JWKS unreachable |
| `SESSION_COOKIE_DOMAIN` | `iovalence.com` |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,cvat-server,iov.iovalence.com` |

---

## Key Files

| File | Purpose |
|------|---------|
| `cvat/auth.py` | Custom Keycloak JWT auth backend (Bearer token path) |
| `cvat/apps/iam/pipeline.py` | Social auth pipeline steps (web UI login path) |
| `cvat/settings/base.py` | Django settings — `SOCIAL_AUTH_PIPELINE`, `DEFAULT_AUTHENTICATION_CLASSES`, `IAM_*` roles |
| `cvat/apps/iam/signals.py` | `post_save` signal — adds users to Django groups based on `is_superuser/is_staff` |
| `cvat/apps/iam/middleware.py` | `ContextMiddleware` — reads user's Django group → sets `privilege` for OPA |
| `cvat/apps/iam/rules/utils.rego` | OPA policy utils — `ADMIN/USER/WORKER` privilege constants |
| `docker-compose.yml` | Service definitions, Keycloak env vars, Traefik labels |
