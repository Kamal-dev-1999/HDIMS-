from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from cryptography.fernet import Fernet, InvalidToken

# Encryption key
SECRET_KEY = b'603zgLcePQ9gH7Ja7y4IvuyTKbLNEgC3KqHv4IVFNlw='
cipher_suite = Fernet(SECRET_KEY)

class AdminUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required.")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.is_active = True
        user.set_password(password)  # Encrypt and store the password
        user.save()
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if not extra_fields.get('is_staff'):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get('is_superuser'):
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, username, password, **extra_fields)


class AdminUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    encrypted_password = models.BinaryField()  # Store the encrypted password
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    last_login = models.DateTimeField(auto_now=True, null=True)

    # Custom related_name to avoid clashes with auth.User
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='admin_users',  # Avoid conflict by renaming reverse accessor
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='admin_users',  # Avoid conflict by renaming reverse accessor
        blank=True
    )

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = AdminUserManager()

    def set_password(self, password):
        """Encrypt and securely store the password."""
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




class Hospital(models.Model):
    name = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    total_beds = models.IntegerField()
    available_beds = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Doctor(models.Model):
    name = models.CharField(max_length=255)
    specialization = models.CharField(max_length=255)
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='doctors')
    is_available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.specialization}"


class Resource(models.Model):
    RESOURCE_TYPES = [
        ('equipment', 'Equipment'),
        ('medicine', 'Medicine'),
    ]
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=50, choices=RESOURCE_TYPES)
    quantity = models.IntegerField()
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='resources')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.type})"


class Alert(models.Model):
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='alerts')
    message = models.TextField()
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Alert for {self.hospital.name}"


class Report(models.Model):
    REPORT_TYPES = [
        ('incident', 'Incident'),
        ('performance', 'Performance'),
    ]
    title = models.CharField(max_length=255)
    type = models.CharField(max_length=50, choices=REPORT_TYPES)
    content = models.TextField()
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"{self.title} - {self.type}"


class Communication(models.Model):
    sender = models.ForeignKey(AdminUser, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(AdminUser, on_delete=models.CASCADE, related_name='received_messages')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.sender.username} to {self.receiver.username}"


class ProgramPerformance(models.Model):
    program_name = models.CharField(max_length=255)
    statistics = models.JSONField()
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='program_performance')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.program_name


class AuditLog(models.Model):
    user = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True)
    action = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username if self.user else 'System'}: {self.action}"


class IncidentReport(models.Model):
    title = models.CharField(max_length=255)
    details = models.TextField()
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='incident_reports')
    is_resolved = models.BooleanField(default=False)
    reported_by = models.ForeignKey(AdminUser, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Incident: {self.title}"