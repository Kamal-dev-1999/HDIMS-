from django.shortcuts import render
from rest_framework.response import Response

# Create your views here.
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from hos_mobile.auth import HospitalTokenAuthentication

class HospitalDashboardAPIView(APIView):
    authentication_classes = [HospitalTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Welcome to the Hospital Dashboard!"})
