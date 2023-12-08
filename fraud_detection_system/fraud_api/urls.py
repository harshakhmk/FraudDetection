# fraud_api/urls.py

from rest_framework import routers
from django.urls import path, include,reverse
from .views import TransactionViewSet, AlertViewSet, DocumentViewSet
from .views import * #CustomSignupView, CustomLoginView, CustomLogoutView, CustomPasswordChangeView, CustomUserProfileView
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
router = routers.DefaultRouter()

router.register(r'transactions', TransactionViewSet, basename='transaction')
router.register(r'alerts', AlertViewSet, basename='alert')
router.register(r'documents', DocumentViewSet, basename='document')

urlpatterns = [
    path('', include(router.urls)),
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email/", VerifyUserEmail.as_view(), name="verify-email"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path('transactions/<int:pk>/', TransactionViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'})),
    path('alerts/<int:pk>/', AlertViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'})),
    path('documents/<int:pk>/', DocumentViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'})),
    path('transactions/', TransactionViewSet.as_view({'post': 'create'},{'get':'list'})),
    path('alerts/', AlertViewSet.as_view({'get':'list'},{'post': 'create'})),
    path('documents/', AlertViewSet.as_view({'get':'list'},{'post': 'create'})),
]
