from django.db import models
from cryptography.fernet import Fernet, InvalidToken
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

# Encryption key
SECRET_KEY = b'603zgLcePQ9gH7Ja7y4IvuyTKbLNEgC3KqHv4IVFNlw='
cipher_suite = Fernet(SECRET_KEY)

class PatientManager(BaseUserManager):
    def create_user(self, email, username, password, **extra_fields):
        if not email:
            raise ValueError("The email is required.")
        if not username:
            raise ValueError("The username is required.")
        
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.is_active = True
        user.is_patient = True  # Ensure patient role
        user.set_password(password)  # Encrypt and set the password
        user.save()
        return user

    def create_superuser(self, email, username, password, **extra_fields):
        # Set default fields for superusers
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_patient', False)  # Superusers are not patients
        
        if not extra_fields.get('is_staff'):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get('is_superuser'):
            raise ValueError("Superuser must have is_superuser=True.")
        
        return self.create_user(email, username, password, **extra_fields)


class PatientUser(AbstractBaseUser):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    encrypted_password = models.BinaryField()  # Encrypted password storage
    is_staff = models.BooleanField(default=False)  # Required for admin access
    is_superuser = models.BooleanField(default=False)  # For superusers
    is_active = models.BooleanField(default=True)  # Account activation
    is_patient = models.BooleanField(default=True)  # Role identifier
    last_login = models.DateTimeField(auto_now=True, null=True)

    # Fields for authentication
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    # Assign custom manager
    objects = PatientManager()

    def set_password(self, password):
        """Encrypt and store the password securely."""
        self.encrypted_password = cipher_suite.encrypt(password.encode())

    def check_password(self, password):
        """Decrypt and validate the password."""
        try:
            decrypted_password = cipher_suite.decrypt(self.encrypted_password).decode()
            return password == decrypted_password
        except InvalidToken:
            return False

    def has_module_perms(self, app_label):
        """Grant module-level permissions."""
        return True

    def has_perm(self, perm, obj=None):
        """Grant specific object-level permissions."""
        return True

    def __str__(self):
        """Readable representation."""
        return self.username
