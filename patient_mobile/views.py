from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import PatientCreateUserSerializer, PatientLoginSerializer, PatientUserSerializer
from rest_framework_simplejwt.tokens import RefreshToken

class PatientSignupAPIView(APIView):
    def post(self, request):
        serializer = PatientCreateUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Patient registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PatientLoginAPIView(APIView):
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
