from knox.auth import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AdminTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, token):
        user, auth_token = super().authenticate_credentials(token)
        if user.user_type != 'admin':
            raise AuthenticationFailed("Invalid token for admin.")
        return user, auth_token
