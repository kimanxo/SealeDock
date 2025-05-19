from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from .utils import format_size

# ========== Media ==========


class Media(models.Model):
    file = models.FileField(upload_to="media/")
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, )
    metadata = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        default= timezone.now() + timedelta(hours=6)
    )
    key = models.CharField(max_length=255, null=False, blank=False)
    groups = models.ManyToManyField("Group", related_name="media", blank=True)  
    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if self.file and not self.metadata:
            self.metadata = {
                "size": format_size(self.file.size),
                # "type": self.file.content_type,
                "name": self.file.name,
            }
        if not self.name:
            self.name = self.file.name
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def is_accessible_by(self, user):
        # Owner always has access
        if self.owner == user:
            return True
        # Members of associated groups have access
        member_ids = Member.objects.filter(user=user).values_list("id", flat=True)
        return self.groups.filter(members__id__in=member_ids).exists()





class Member(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(
        choices=[("owner", "Owner"), ("admin", "Admin"), ("member", "Member")],
        max_length=6,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username


class Group(models.Model):
    name = models.CharField(max_length=100)
    members = models.ManyToManyField(Member, related_name="groups")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    
    
    def __str__(self):
        return self.name


class GroupInvite(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        default= timezone.now() + timedelta(days=2)
    )

    def is_valid(self):
        return timezone.now() <= self.expires_at


# # ========== Access Links ==========


class PreviewLink(models.Model):
    media = models.ForeignKey(Media, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        default= timezone.now() + timedelta(hours=6)
    )

    def is_valid(self):
        return self.enabled and timezone.now() <= self.expires_at


class OneTimeKey(models.Model):
    media = models.ForeignKey(Media, on_delete=models.CASCADE)
    key = models.CharField(max_length=255, unique=True)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)




class ActivityLog(models.Model):
    EVENT_TYPES = [
        ("media_download", "Media Download"),
        ("media_preview", "Media View"),
        ("group_invite_preview", "Group Invite Used"),
        ("member_joined_group", "Member Joined Group"),
    ]

    # Who performed the action (e.g., downloaded the file)
    actor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="activity_logs")

    # Who owns the resource being acted upon (e.g., owner of the file)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owned_activity_logs")

    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    # Context
    media = models.ForeignKey("Media", on_delete=models.SET_NULL, null=True, blank=True)
    group = models.ForeignKey("Group", on_delete=models.SET_NULL, null=True, blank=True)
    invite = models.ForeignKey("GroupInvite", on_delete=models.SET_NULL, null=True, blank=True)

    additional_data = models.JSONField(null=True, blank=True)

    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.event_type} by {self.actor or 'Unknown'} on {self.owner.username}'s data"



