from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from .utils import format_size

# ========== Media Model ==========
class Media(models.Model):
    """
    Represents a media file uploaded by a user.
    
    Attributes:
        file (FileField): The uploaded file stored in 'media/' directory.
        name (CharField): The display name of the media.
        owner (ForeignKey): Reference to the User who owns the media.
        metadata (JSONField): Optional JSON metadata such as file size and name.
        created_at (DateTimeField): Timestamp when the media was uploaded.
        expires_at (DateTimeField): When the media access expires (default 6 hours after creation).
        key (CharField): A unique key associated with the media (used for access or security).
        groups (ManyToManyField): Groups that have access to this media.
    """

    file = models.FileField(upload_to="media/")
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    metadata = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=timezone.now() + timedelta(hours=6))
    key = models.CharField(max_length=255, null=False, blank=False)
    groups = models.ManyToManyField("Group", related_name="media", blank=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        """
        Override save method to auto-populate metadata if missing,
        and default the media name to the uploaded file's name if not provided.
        """
        if self.file and not self.metadata:
            self.metadata = {
                "size": format_size(self.file.size),  # Format size as human-readable string
                # "type": self.file.content_type,     # Uncomment if content type is needed
                "name": self.file.name,
            }
        if not self.name:
            self.name = self.file.name
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if the media has expired based on expires_at."""
        return timezone.now() > self.expires_at

    def is_accessible_by(self, user):
        """
        Determine if a given user has access to the media.
        Access is granted if:
            - The user is the owner.
            - The user is a member of any group associated with this media.
        """
        if self.owner == user:
            return True
        member_ids = Member.objects.filter(user=user).values_list("id", flat=True)
        return self.groups.filter(members__id__in=member_ids).exists()


# ========== Member Model ==========
class Member(models.Model):
    """
    Represents a membership relation between a User and a Group,
    with an assigned role in that group.
    
    Attributes:
        user (ForeignKey): The user who is a member.
        role (CharField): Role of the member in the group (owner, admin, or member).
        created_at (DateTimeField): When the membership was created.
        updated_at (DateTimeField): When the membership was last updated.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(
        choices=[("owner", "Owner"), ("admin", "Admin"), ("member", "Member")],
        max_length=6,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username


# ========== Group Model ==========
class Group(models.Model):
    """
    Represents a group of users.
    
    Attributes:
        name (CharField): Name of the group.
        members (ManyToManyField): Members of the group (Member instances).
        created_at (DateTimeField): Timestamp when the group was created.
        updated_at (DateTimeField): Timestamp of last group update.
    """

    name = models.CharField(max_length=100)
    members = models.ManyToManyField(Member, related_name="groups")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


# ========== GroupInvite Model ==========
class GroupInvite(models.Model):
    """
    Represents an invitation token to join a group.
    
    Attributes:
        group (ForeignKey): The group the invitation belongs to.
        token (CharField): Unique invitation token string.
        created_at (DateTimeField): When the invite was created.
        expires_at (DateTimeField): When the invite expires (default 2 days after creation).
    """

    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=timezone.now() + timedelta(days=2))

    def is_valid(self):
        """Check if the invitation is still valid (not expired)."""
        return timezone.now() <= self.expires_at


# ========== PreviewLink Model ==========
class PreviewLink(models.Model):
    """
    Temporary access link to preview a media file.
    
    Attributes:
        media (ForeignKey): The media this preview link references.
        token (CharField): Unique token to access the preview.
        created_at (DateTimeField): When the preview link was created.
        expires_at (DateTimeField): When the preview link expires (default 6 hours).
        enabled (Boolean): Whether this preview link is enabled (assumed missing in your snippet, but used in is_valid).
    """

    media = models.ForeignKey(Media, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=timezone.now() + timedelta(hours=6))
    enabled = models.BooleanField(default=True)  # Added, as used in is_valid method

    def is_valid(self):
        """Check if the preview link is enabled and not expired."""
        return self.enabled and timezone.now() <= self.expires_at


# ========== OneTimeKey Model ==========
class OneTimeKey(models.Model):
    """
    One-time access key associated with a media file.
    
    Attributes:
        media (ForeignKey): The media the key grants access to.
        key (CharField): Unique one-time key string.
        used (Boolean): Whether this key has been used.
        created_at (DateTimeField): When the key was created.
    """

    media = models.ForeignKey(Media, on_delete=models.CASCADE)
    key = models.CharField(max_length=255, unique=True)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


# ========== ActivityLog Model ==========
class ActivityLog(models.Model):
    """
    Logs activity events related to media and group interactions.
    
    Attributes:
        actor (ForeignKey): The user who performed the action (nullable).
        owner (ForeignKey): The owner of the resource involved.
        event_type (CharField): Type of event (media download, preview, invite used, member joined).
        ip_address (GenericIPAddressField): IP address of the actor (optional).
        media (ForeignKey): Related media, if applicable.
        group (ForeignKey): Related group, if applicable.
        invite (ForeignKey): Related group invite, if applicable.
        additional_data (JSONField): Optional extra data for the event.
        timestamp (DateTimeField): When the event occurred.
    """

    EVENT_TYPES = [
        ("media_download", "Media Download"),
        ("media_preview", "Media View"),
        ("group_invite_preview", "Group Invite Used"),
        ("member_joined_group", "Member Joined Group"),
    ]

    actor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="activity_logs")
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owned_activity_logs")
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    media = models.ForeignKey(Media, on_delete=models.SET_NULL, null=True, blank=True)
    group = models.ForeignKey(Group, on_delete=models.SET_NULL, null=True, blank=True)
    invite = models.ForeignKey(GroupInvite, on_delete=models.SET_NULL, null=True, blank=True)

    additional_data = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        actor_str = self.actor.username if self.actor else "Unknown"
        return f"{self.event_type} by {actor_str} on {self.owner.username}'s data"
