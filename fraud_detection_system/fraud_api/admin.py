# fraud_api/admin.py

from django.contrib import admin
from .models import Transaction, Alert, Document,User

admin.site.register(User)

"""@admin.register(CustomUser)
class CustomerUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'date_joined','contact_number')
    list_filter = ('email', 'date_joined','contact_number')
    search_fields = ('email', 'first_name', 'contact_number')
    date_hierarchy = 'date_joined'
"""

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('user', 'amount', 'description', 'timestamp')
    list_filter = ('user', 'timestamp')
    search_fields = ('user__username', 'amount', 'description')
    date_hierarchy = 'timestamp'

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('transaction', 'description', 'created_at')
    list_filter = ('transaction__user', 'created_at')
    search_fields = ('transaction__user__username', 'description')
    date_hierarchy = 'created_at'

@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('transaction', 'file', 'created_at')
    list_filter = ('transaction__user', 'created_at')
    search_fields = ('transaction__user__username', 'file')
    date_hierarchy = 'created_at'
