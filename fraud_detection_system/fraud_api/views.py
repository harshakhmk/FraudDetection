from django.shortcuts import render,redirect,reverse
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Transaction, Alert, Document, User
from .serializers import TransactionSerializer, AlertSerializer, DocumentSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework import status
from rest_framework.response import Response
#from allauth.account.views import SignupView, LoginView, LogoutView, PasswordChangeView
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from django.views.decorators.csrf import csrf_protect
from rest_framework.authtoken.models import Token
from rest_framework import permissions
from utils.permission import *
from .kafka_producer import *
from .redis import *
from .utility import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status, generics, views
from .serializers import (
    ResetPasswordSerializer,
    RegisterUserSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
)
from django.db import transaction
from django.contrib.sites.shortcuts import get_current_site
from utils.email import Util
from django.conf import settings
from utils.notifications import Notifications
admin_user = User.objects.all().filter(is_superuser=True)
#bot_user = User.objects.get(email="kharshakashyap@gmail.com")


def upload_document(request):
    # Process document upload logic
    document_data = process_uploaded_document(request.FILES['document'])
    # Send a Kafka message
    #produce_message('document-upload', document_data)
    # Rest of your view logic
    return document_data


def analyse_financial_record(document,request):
    cached_result = get_cached_analysis_result(document.id)

    if cached_result:
        return Response(cached_result, status=status.HTTP_200_OK)

    analysis_result = analyse_record(request.data)

    # Cache the analysis result in Redis
    cache_analysis_result(document.id, analysis_result)

     # Send a Kafka message
    produce_message('analyse-financial-records', analysis_result)

    return Response(analysis_result, status=status.HTTP_200_OK)


# Create your views here.
class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterUserSerializer
    queryset = User.objects.all()

    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        # now user is created
        user_data = serializer.data
        user = User.objects.get(email=user_data.get("email"))
        token = RefreshToken.for_user(user).access_token
        current_domain = get_current_site(request).domain
        relative_url = reverse("verify-email")
        absolute_url = (
            "http://" + current_domain + relative_url + "?token=" + str(token)
        )
        message_body = (
            f"Hi {user.username}, please verify your email address from below link\n"
            + absolute_url
        )
        email_data = {
            "body": message_body,
            "subject": "Verify your email",
            "to_email": user.email,
        }
        Util.send_email(email_data)
        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyUserEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    token_param = openapi.Parameter(
        "token",
        in_=openapi.IN_QUERY,
        description="Enter token to verify your account",
        type=openapi.TYPE_STRING,
    )

    @swagger_auto_schema(manual_parameters=[token_param])
    def get(self, request):
        token = request.GET.get("token")
        try:
            data = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.filter(id=data["user_id"])
            if user.is_verified:
                return Response(
                    {"message": "Already verified"}, status=status.HTTP_200_OK
                )

            user.is_verified = True
            user.save()
            Notifications.send_notification(admin_user, user,f"Dear {user.username} your account is successfully verified")
            return Response(
                {"message": "Successfully verified"}, status=status.HTTP_200_OK
            )
        except jwt.ExpiredSignatureError as e:
            return Response(
                {"message": "Activation link Expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except jwt.Exceptions.DecodeError as de:
            return Response(
                {"message": "Invalid Token"}, status=status.HTTP_400_BAD_REQUEST
            )


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        # data = request.data
        # #user_data = serializer.data
        # user = User.objects.get(email=user_data.get("email"))
        # print(serializer.__dir__())
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status.HTTP_200_OK)


class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        data = {"request": request, "data": request.data}
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request):
        pass


class TransactionViewSet(viewsets.ModelViewSet):
    serializer_class = TransactionSerializer
    permission_classes = (IsAuthenticated, IsOwner,)

    @swagger_auto_schema(
        operation_description="List all transactions for the authenticated user",
        responses={200: TransactionSerializer(many=True)},
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new transaction",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'amount': openapi.Schema(type=openapi.TYPE_NUMBER, description='Transaction amount'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction description (optional)'),
                # Add more fields here
            }
        ),
        responses={201: TransactionSerializer()},
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Retrieve a transaction by ID",
        responses={200: TransactionSerializer()},
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    

    @swagger_auto_schema(
        operation_description="Update a transaction by ID",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'amount': openapi.Schema(type=openapi.TYPE_NUMBER, description='Transaction amount'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Transaction description (optional)'),
                # Add more fields here
            }
        ),
        responses={200: TransactionSerializer()},
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Delete a transaction by ID",
        responses={204: "No content"},
    )
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    def get_queryset(self):
        # Check if the user is authenticated
        if self.request.user.is_authenticated:
           # Filter transactions for the current authenticated user
           return Transaction.objects.filter(user=self.request.user)
        else:
           # Handle the case when the user is not authenticated
            return Transaction.objects.none()  # Or any other appropriate action
    

class AlertViewSet(viewsets.ModelViewSet):
    serializer_class = AlertSerializer
    permission_classes = (IsAuthenticated, IsOwner,)
    queryset = Alert.objects.all()

    @swagger_auto_schema(
        operation_description="List all alerts for the authenticated user",
        responses={200: AlertSerializer(many=True)},
    )
    def list(self, request, *args, **kwargs):
        alerts = self.get_queryset().filter(transaction__user=request.user)
        serializer = self.get_serializer(alerts, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Create a new alert",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'transaction': openapi.Schema(type=openapi.TYPE_INTEGER, description='Transaction ID'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Alert description'),
                # Add more fields here
            }
        ),
        responses={201: AlertSerializer()},
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        operation_description="Retrieve an alert by ID",
        responses={200: AlertSerializer()},
    )
    def retrieve(self, request, *args, **kwargs):
        alert = self.get_object()
        self.check_object_permissions(self.request, alert)
        serializer = self.get_serializer(alert)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Update an alert by ID",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'transaction': openapi.Schema(type=openapi.TYPE_INTEGER, description='Transaction ID'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Alert description'),
                # Add more fields here
            }
        ),
        responses={200: AlertSerializer()},
    )
    def update(self, request, *args, **kwargs):
        alert = self.get_object()
        self.check_object_permissions(self.request, alert)
        serializer = self.get_serializer(alert, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Delete an alert by ID",
        responses={204: "No content"},
    )
    def destroy(self, request, *args, **kwargs):
        alert = self.get_object()
        self.check_object_permissions(self.request, alert)
        alert.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = (IsAuthenticated, IsOwner,)
    queryset = Document.objects.all()

    @swagger_auto_schema(
        operation_description="List all documents for the authenticated user",
        responses={200: DocumentSerializer(many=True)},
    )
    def list(self, request, *args, **kwargs):
        documents = self.get_queryset().filter(transaction__user=request.user)
        serializer = self.get_serializer(documents, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Create a new document",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'transaction': openapi.Schema(type=openapi.TYPE_INTEGER, description='Transaction ID'),
                'document_file': openapi.Schema(type=openapi.TYPE_FILE, description='Document file'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Document description'),
                # Add more fields here
            }
        ),
        responses={201: DocumentSerializer()},
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        document = serializer.save()
         # Process the uploaded document to extract transaction details
        transactions = extract_transactions(request.data['file'])

        if transactions==[]:
            return Response("Invalid document",status=status.HTTP_404_ERROR)

        # Create transaction objects and associate them with the document
        for transaction_data in transactions:
            Transaction.objects.create(document=document, **transaction_data)

        # Process document upload logic
        document_data = upload_document(request)
        analyse_financial_record(document, document_data) 
        return Response("Document uploaded successfully", status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        operation_description="Retrieve a document by ID",
        responses={200: DocumentSerializer()},
    )
    def retrieve(self, request, *args, **kwargs):
        document = self.get_object()
        self.check_object_permissions(self.request, document)
        serializer = self.get_serializer(document)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Update a document by ID",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'transaction': openapi.Schema(type=openapi.TYPE_INTEGER, description='Transaction ID'),
                'document_file': openapi.Schema(type=openapi.TYPE_FILE, description='Document file'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Document description'),
                # Add more fields here
            }
        ),
        responses={200: DocumentSerializer()},
    )
    def update(self, request, *args, **kwargs):
        document = self.get_object()
        self.check_object_permissions(self.request, document)
        serializer = self.get_serializer(document, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # remove the old data of document.id in redis
        delete_key_from_redis(document.id)
        
        # Update transaction details for this object
        with transaction.atomic():
            # Extract transactions from the updated document
            transactions = extract_transactions(request.data['document_file'])
            
            # Delete all existing transactions associated with the current document
            document.transaction_set.all().delete()

            # Save the updated document
            document = serializer.save()

            # Create new transaction objects and associate them with the document
            for transaction_data in transactions:
                Transaction.objects.create(document=document, **transaction_data)

        # Process document upload logic
        
        document_data = upload_document(request)
        analyse_financial_record(document, document_data) 
        return Response("Document updated successfully", status=status.HTTP_201_CREATED)
        #return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Delete a document by ID",
        responses={204: "No content"},
    )
    def destroy(self, request, *args, **kwargs):
        document = self.get_object()
        self.check_object_permissions(self.request, document)
        delete_key_from_redis(document.id)
        document.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
