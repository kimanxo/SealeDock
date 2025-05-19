from django import template

register = template.Library()

@register.filter
def is_owner(group, user):
    """
    Template filter to check if the given user is the owner of the group.

    Args:
        group: Group instance to check membership for.
        user: User instance to verify ownership.

    Returns:
        bool: True if the user is an owner of the group, False otherwise.
    """
    return group.members.filter(user=user, role="owner").exists()


@register.filter
def can_invite(group, user):
    """
    Template filter to check if the user has permission to invite others to the group.
    Only users with 'admin' or 'owner' roles can invite.

    Args:
        group: Group instance to check membership for.
        user: User instance to verify invitation rights.

    Returns:
        bool: True if user has 'admin' or 'owner' role in the group, False otherwise.
    """
    return group.members.filter(user=user, role__in=["admin", "owner"]).exists()


@register.filter
def is_file_owner(media, user):
    """
    Template filter to check if the given user is the owner of a media file.

    Args:
        media: Media instance to check ownership.
        user: User instance to verify ownership.

    Returns:
        bool: True if user owns the media, False otherwise.
    """
    return media.owner == user
