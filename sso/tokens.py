"""
Custom JWT token classes with additional claims
"""
from rest_framework_simplejwt.tokens import RefreshToken as BaseRefreshToken


class CustomRefreshToken(BaseRefreshToken):
    """
    Custom refresh token that includes additional user claims.
    """
    @classmethod
    def for_user(cls, user):
        """
        Generate token with custom claims for user.
        """
        token = super().for_user(user)

        # Add custom claims
        token['email'] = user.email if user.email else ''
        token['is_sso_admin'] = user.is_sso_admin
        token['auth_type'] = user.auth_type
        token['is_anonymous'] = user.is_anonymous
        token['display_name'] = user.display_name

        return token
