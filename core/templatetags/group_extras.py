from django import template

register = template.Library()

@register.filter
def is_owner(group, user):
    return group.members.filter(user=user, role="owner").exists()



@register.filter
def can_invite(group, user):
    return group.members.filter(user=user, role__in=["admin", "owner"]).exists()



@register.filter
def is_file_owner(media, user):
    return media.owner == user 