from knox.auth import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

class PatientTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, token):
        user, auth_token = super().authenticate_credentials(token)
        if user.user_type != 'patient':
            raise AuthenticationFailed("Invalid token for patient.")
        return user, auth_token
