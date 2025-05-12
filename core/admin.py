from django.contrib import admin

from .models import Media,  Member, Group, GroupInvite, PreviewLink, OneTimeKey


admin.site.register(Media)
admin.site.register(Member)
admin.site.register(Group)
admin.site.register(GroupInvite)
admin.site.register(PreviewLink)
admin.site.register(OneTimeKey)

