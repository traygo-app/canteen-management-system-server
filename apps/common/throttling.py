from rest_framework.throttling import SimpleRateThrottle


class VerifiedUserThrottle(SimpleRateThrottle):
    scope = "verified"

    def get_cache_key(self, request, view):
        if not request.user.is_authenticated:
            return None
        if not getattr(request.user, "is_verified", False):
            return None
        return self.cache_format % {
            "scope": self.scope,
            "ident": request.user.pk,
        }


class UnverifiedUserThrottle(SimpleRateThrottle):
    scope = "unverified"

    def get_cache_key(self, request, view):
        if not request.user.is_authenticated:
            return None
        if getattr(request.user, "is_verified", False):
            return None
        return self.cache_format % {
            "scope": self.scope,
            "ident": request.user.pk,
        }
