from django.contrib import admin

from .models import Media,  Member, Group, GroupInvite


admin.site.register(Media)
admin.site.register(Member)
admin.site.register(Group)
admin.site.register(GroupInvite)


