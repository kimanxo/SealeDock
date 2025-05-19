from django.views.generic.base import View
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from django.utils import timezone
from django.http import HttpResponse, JsonResponse
from django.db.models import Q, Prefetch
from django.urls import reverse
from datetime import timedelta
import secrets
import os
from core.utils import get_client_ip
from core.forms import GroupForm
from core.models import Media, Group, Member, PreviewLink, OneTimeKey, GroupInvite, ActivityLog


def get_client_ip(request):
    """Utility function to get client's real IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


@login_required
def create_group(request):
    """
    View to handle group creation via POST form submission.
    Automatically assigns the current user as 'owner' of the group.
    """
    if request.method == "POST":
        form = GroupForm(request.POST)
        if form.is_valid():
            group = form.save()
            # Add current user as owner
            member = Member.objects.create(user=request.user, role='owner')
            group.members.add(member)

            response = HttpResponse()
            response["HX-Redirect"] = reverse("group_list")
            return response
    else:
        form = GroupForm()
    return render(request, 'partials/create_group.html', {'form': form})


@login_required
def generate_link(request, pk):
    """
    Generate a one-time invite link for a group.
    Token is saved in the GroupInvite instance.
    """
    group = get_object_or_404(Group, pk=pk)

    token = secrets.token_urlsafe(24)
    group_invite_link = GroupInvite.objects.create(
        group=group,
        token=token,
        expires_at=timezone.now() + timedelta(hours=6)
    )

    invitation_link = f"{request.build_absolute_uri('/')[:-1]}/group/join/{token}"
    return JsonResponse({"invitation_link": invitation_link})


@login_required
def join_group(request, token):
    """
    View to handle group join via invite token.
    If valid, adds the user as a member and logs the event.
    """
    invitation = get_object_or_404(GroupInvite, token=token)

    if not invitation.is_valid():
        return render(request, "error.html", {
            "error": "The invitation link is either expired or used, please request a new one from the issuer."
        }, status=403)

    group = invitation.group

    if request.method == "POST":
        if not group.members.filter(user=request.user).exists():
            member = Member.objects.create(user=request.user, role='member')
            group.members.add(member)

            ActivityLog.objects.create(
                actor=request.user,
                owner=group.members.filter(role="owner").first().user,
                event_type="member_joined_group",
                ip_address=get_client_ip(request),
                group=group,
                invite=invitation,
            )

        invitation.save()
        return redirect(reverse("group_list"))

    # Log preview event
    ActivityLog.objects.create(
        actor=request.user,
        owner=group.members.filter(role="owner").first().user,
        event_type="group_invite_preview",
        ip_address=get_client_ip(request),
        group=group,
        invite=invitation,
    )

    return render(request, "invitation_preview.html", {
        "token": token,
        "invitation": invitation
    })


class GroupListView(LoginRequiredMixin, ListView):
    """
    List all groups the user is a member of.
    """
    model = Group
    template_name = "groups.html"
    context_object_name = "group_list"

    def get_queryset(self):
        return Group.objects.filter(
            members__user=self.request.user
        ).prefetch_related('members').distinct()


class GroupDeleteView(LoginRequiredMixin, View):
    """
    Delete a group, its members, and associated media if the user is the owner.
    Uses safe checks and logs errors as appropriate.
    """

    def post(self, request):
        try:
            group = Group.objects.get(pk=request.POST.get("pk"))
        except Group.DoesNotExist:
            response = HttpResponse("Group not found", status=404)
            response["HX-Retarget"] = "#errors"
            response["HX-Reswap"] = "innerHTML"
            return response

        if not group.members.filter(user=request.user, role="owner").exists():
            response = HttpResponse("You do not have permission to delete this group", status=403)
            response["HX-Retarget"] = "#errors"
            response["HX-Reswap"] = "innerHTML"
            return response

        # Remove related members and media
        group.members.clear()

        for media in group.media.all():
            # Safely delete the associated file from disk
            if media.file and os.path.isfile(media.file.path):
                try:
                    os.remove(media.file.path)
                except Exception:
                    pass  # log exception if needed
            media.delete()

        group.delete()

        response = render(
            request,
            "partials/groups_rows.html",
            {"group_list": Group.objects.filter(members__user=self.request.user)},
        )
        response["HX-Retarget"] = ".tbody"
        response["HX-Reswap"] = "outerHTML"
        return response


class GroupDetailView(LoginRequiredMixin, View):
    """
    View detailed content (e.g., media) of a group the user is a member of.
    """

    def get(self, request, pk):
        group = get_object_or_404(
            Group.objects.filter(members__user=request.user).prefetch_related("media").distinct(), pk=pk
        )
        return render(
            request,
            "group_files.html",
            {"group": group},
        )
