from knox.auth import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

class HospitalTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, token):
        user, auth_token = super().authenticate_credentials(token)
        if user.user_type != 'hospital':
            raise AuthenticationFailed("Invalid token for hospital.")
        return user, auth_token
