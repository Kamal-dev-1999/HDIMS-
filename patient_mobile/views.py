from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import PatientCreateUserSerializer, PatientLoginSerializer, PatientUserSerializer

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated

class PatientSignupAPIView(APIView):
    permission_classes = [AllowAny]


class PatientSignupAPIView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access signup


    def post(self, request):
        serializer = PatientCreateUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Patient registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from patient_mobile.auth import PatientTokenAuthentication

class PatientDashboardAPIView(APIView):
    authentication_classes = [PatientTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Welcome to the Patient Dashboard!"})


class PatientLoginAPIView(APIView):
    permission_classes = [AllowAny]


class PatientLoginAPIView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access login


    def post(self, request):
        serializer = PatientLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": PatientUserSerializer(user).data
            })
        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
