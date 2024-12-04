from django.urls import path
from .views import PatientSignupAPIView, PatientLoginAPIView

urlpatterns = [
    path('signup/', PatientSignupAPIView.as_view(), name='patient_signup'),
    path('login/', PatientLoginAPIView.as_view(), name='patient_login'),
]
