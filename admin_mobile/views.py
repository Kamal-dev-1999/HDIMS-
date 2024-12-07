from .serializers import AdminCreateUserSerializer, AdminLoginSerializer, AdminUserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers, status, views
from rest_framework.response import Response
from .models import Hospital, Doctor, Resource, Alert, Report, Communication, ProgramPerformance, AuditLog, IncidentReport
from .serializers import (
    HospitalSerializer, DoctorSerializer, ResourceSerializer, AlertSerializer,
    ReportSerializer, CommunicationSerializer, ProgramPerformanceSerializer,
    AuditLogSerializer, IncidentReportSerializer
)
from admin_mobile.auth import AdminTokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny


class AdminSignupAPIView(APIView):
    permission_classes= [AllowAny]
    """Handles admin signup."""
    def post(self, request):
        serializer = AdminCreateUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Admin registered successfully."}, 
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminLoginAPIView(APIView):
   
    authentication_classes = [AdminTokenAuthentication] 
    permission_classes= [AllowAny]
    """Handles admin login."""
    def post(self, request):
        serializer = AdminLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": f"Welcome back, Admin {user.username}!",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": AdminUserSerializer(user).data,
                "admin_role": "Full administrative privileges granted."
            }, status=status.HTTP_200_OK)
        return Response(
            {"message": "Invalid credentials. Login failed.", "errors": serializer.errors}, 
            status=status.HTTP_401_UNAUTHORIZED
        )




class DataSubmitChoiceSerializer(serializers.Serializer):
    authentication_classes = [AdminTokenAuthentication]
    permission_classes = [IsAuthenticated]

    data_type = serializers.ChoiceField(choices=[
        ('hospital', 'Hospital'),
        ('doctor', 'Doctor'),
        ('resource', 'Resource'),
        ('alert', 'Alert'),
        ('report', 'Report'),
        ('communication', 'Communication'),
        ('program_performance', 'Program Performance'),
        ('audit_log', 'Audit Log'),
        ('incident_report', 'Incident Report')
    ])

class SubmitDataView(views.APIView):
    authentication_classes = [AdminTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # First, let the user choose the data type
        data_type_serializer = DataSubmitChoiceSerializer(data=request.data)
        if data_type_serializer.is_valid():
            data_type = data_type_serializer.validated_data['data_type']
            if data_type == 'hospital':
                serializer = HospitalSerializer(data=request.data)
            elif data_type == 'doctor':
                serializer = DoctorSerializer(data=request.data)
            elif data_type == 'resource':
                serializer = ResourceSerializer(data=request.data)
            elif data_type == 'alert':
                serializer = AlertSerializer(data=request.data)
            elif data_type == 'report':
                serializer = ReportSerializer(data=request.data)
            elif data_type == 'communication':
                serializer = CommunicationSerializer(data=request.data)
            elif data_type == 'program_performance':
                serializer = ProgramPerformanceSerializer(data=request.data)
            elif data_type == 'audit_log':
                serializer = AuditLogSerializer(data=request.data)
            elif data_type == 'incident_report':
                serializer = IncidentReportSerializer(data=request.data)

            # Now validate and save the data for the selected model
            if serializer.is_valid():
                serializer.save()
                return Response({"message": f"{data_type.capitalize()} data submitted successfully."}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(data_type_serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class DisplayAllinfoView(APIView):
    authentication_classes = [AdminTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            # Retrieve data for all hospitals and their related models
            hospital_data = Hospital.objects.all()  # Get all hospitals
            doctor_data = Doctor.objects.all()  # Get all doctors
            resource_data = Resource.objects.all()  # Get all resources
            alert_data = Alert.objects.all()  # Get all alerts
            report_data = Report.objects.all()  # Get all reports
            communication_data = Communication.objects.all()  # Get all communications
            program_performance_data = ProgramPerformance.objects.all()  # Get all program performance data
            audit_log_data = AuditLog.objects.all()  # Get all audit logs
            incident_report_data = IncidentReport.objects.all()  # Get all incident reports

            # Serialize the data
            hospital_serializer = HospitalSerializer(hospital_data, many=True)
            doctor_serializer = DoctorSerializer(doctor_data, many=True)
            resource_serializer = ResourceSerializer(resource_data, many=True)
            alert_serializer = AlertSerializer(alert_data, many=True)
            report_serializer = ReportSerializer(report_data, many=True)
            communication_serializer = CommunicationSerializer(communication_data, many=True)
            program_performance_serializer = ProgramPerformanceSerializer(program_performance_data, many=True)
            audit_log_serializer = AuditLogSerializer(audit_log_data, many=True)
            incident_report_serializer = IncidentReportSerializer(incident_report_data, many=True)

            # Combine all serialized data
            combined_data = {
                "hospital_data": hospital_serializer.data,
                "doctor_data": doctor_serializer.data,
                "resource_data": resource_serializer.data,
                "alert_data": alert_serializer.data,
                "report_data": report_serializer.data,
                "communication_data": communication_serializer.data,
                "program_performance_data": program_performance_serializer.data,
                "audit_log_data": audit_log_serializer.data,
                "incident_report_data": incident_report_serializer.data
            }

            return Response(combined_data, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle any potential errors
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

