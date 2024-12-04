from rest_framework import serializers
from .models import (
    AdminUser, Hospital, Doctor, Resource, Alert,
    Report, Communication, ProgramPerformance, AuditLog, IncidentReport
)

from rest_framework import serializers
from .models import AdminUser

class AdminUserSerializer(serializers.ModelSerializer):
    """
    Serializer for basic AdminUser details.
    """
    class Meta:
        model = AdminUser
        fields = ['id', 'username', 'email']


class AdminCreateUserSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new AdminUser.
    """
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = AdminUser
        fields = ['email', 'username', 'password', 'password2']

    def validate(self, attrs):
        """
        Ensure the passwords match.
        """
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        """
        Create a new AdminUser.
        """
        user = AdminUser(
            email=validated_data['email'],
            username=validated_data['username']
        )
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user


class AdminLoginSerializer(serializers.Serializer):
    """
    Serializer for AdminUser login.
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})

    def validate(self, attrs):
        """
        Validate username and password for login.
        """
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = AdminUser.objects.filter(username=username).first()
            if user and user.check_password(password):
                return user  # Return the authenticated user
            raise serializers.ValidationError("Invalid username or password.")
        raise serializers.ValidationError("Both username and password are required.")



class HospitalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hospital
        fields = '__all__'


class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = '__all__'


class ResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = '__all__'


class CommunicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Communication
        fields = '__all__'


class ProgramPerformanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProgramPerformance
        fields = '__all__'


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = '__all__'


class IncidentReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = IncidentReport
        fields = '__all__'
