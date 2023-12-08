from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin,User
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

class UserManager(BaseUserManager):
     def create_user(self, email, password=None, username=None):
        if username is None:
            username = email.split("@", 1)[0]
        if email is None:
            raise TypeError("Email must not be Empty")
        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

     def create_superuser(self, email, password, username=None):
        if password is None:
            raise TypeError("Password must not be Empty")
        user = self.create_user(email, password, username)
        user.is_staff = True
        user.is_superuser = True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    fullname = models.CharField(
        max_length=255, null=True, blank=True, default="username"
    )
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    ROLE_CHOICES = (
        ('customer', 'Customer'),
        ('system', 'System'),
        ('fraudanalyst', 'FraudAnalyst'),
        ('admin', 'Admin'),
        ('bot', 'Admin'),

    )
    status = models.CharField(max_length=20, choices=ROLE_CHOICES, default='pending')
    role = models.CharField(max_length=50)  # E.g., 'Fraud Analyst', 'Administrator'
    phonenumber = models.CharField(max_length=10, null=True, blank=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELD = ["username","email",'first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        token = RefreshToken.for_user(self)
        return {"refresh_token": str(token), "access_token": str(token.access_token)}

class Document(models.Model):
    title = models.CharField(max_length=100)
    file = models.FileField(upload_to='documents/')
    created_at = models.DateTimeField(auto_now_add=True)


class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True, null=True)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, blank=True, null=True)
    
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('suspicious', 'Suspicious'),
        ('rejected', 'Rejected'),
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    def get_alerts(self):
        return Alert.objects.filter(transaction=self)

    # Adjust any related methods or fields based on the new status field

class Alert(models.Model):
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE)
    alert_type = models.CharField(max_length=50)
    description = models.TextField()
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def mark_as_resolved(self):
        self.is_resolved = True
        self.save()
    
    def mark_as_unresolved(self):
        self.is_resolved = False
        self.save()

    # Adjust any related methods or fields based on the new status field

class CustomModel(models.Model):
    # Define additional models for new features here
    pass

"""
Pending: It means that the system has received the transaction data but has not yet made a determination regarding its legitimacy or whether it is suspicious. Transactions often start in this state before undergoing further analysis.

Approved: The system has reviewed the transaction data and determined that it is legitimate and poses no suspicion of fraud. Approved transactions are typically considered safe and can proceed without additional scrutiny.

Rejected: The system has identified certain characteristics or patterns in the transaction data that raise suspicion of fraudulent activity. As a result, the system rejects the transaction, preventing it from being processed.
"""