from django.contrib import admin

from .models import Media,  Member, Group, GroupInvite, PreviewLink, OneTimeKey, ActivityLog

# Register multiple models to the Django admin site in one statement.
# This allows these models to be managed through the Django admin interface.
admin.site.register([Media,  Member, Group, GroupInvite, PreviewLink, OneTimeKey, ActivityLog])

