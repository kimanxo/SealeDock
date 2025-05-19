from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.core.paginator import Paginator
from django.http import HttpResponse
from core.models import Media, Group, ActivityLog
from core.utils import get_client_ip


@require_http_methods(["GET"])
def index(request):
    """
    Landing page view. Redirects authenticated users to dashboard.
    """
    if request.user.is_authenticated:
        return redirect("/dashboard")
    return render(request, "index.html")


@login_required
def owner_dashboard(request):
    """
    Dashboard view for group/media owners.
    Displays:
    - Groups the user owns
    - Media the user owns
    - Activity logs related to the above
    """
    # Query user's owned groups and media
    owned_groups = Group.objects.filter(
        members__user=request.user, members__role="owner"
    ).distinct()

    owned_media = Media.objects.filter(owner=request.user)

    # Related logs for owned media or groups
    logs = ActivityLog.objects.filter(
        Q(media__in=owned_media) | Q(group__in=owned_groups)
    ).select_related("actor", "media", "group").order_by("-timestamp")

    # Paginate logs (10 per page)
    paginator = Paginator(logs, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(request, "dashboard.html", {
        "owned_groups": owned_groups,
        "owned_media": owned_media,
        "logs": page_obj,
    })
