from django.urls import path
from .views import AdminSignupAPIView, AdminLoginAPIView , DisplayAllinfoView
from .views import SubmitDataView


urlpatterns = [
    path('signup/', AdminSignupAPIView.as_view(), name='admin-signup'),
    path('login/', AdminLoginAPIView.as_view(), name='admin-login'),
    path('submit-data/', SubmitDataView.as_view(), name='submit_data'),
    path('hospital/all-data/', DisplayAllinfoView.as_view(), name='display-all-info'),
]
