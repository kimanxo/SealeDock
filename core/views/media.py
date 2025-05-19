from django.views.generic.base import View
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, Http404, JsonResponse
from django.views.generic import ListView
from django.utils import timezone
from django.conf import settings
from django.core.files.base import ContentFile
import os
import uuid
import mimetypes
import secrets
from datetime import timedelta

from core.forms import MediaUploadForm
from core.models import Media, Member, PreviewLink, OneTimeKey, ActivityLog
from core.utils import Encryptor, get_client_ip


class MediaListView(LoginRequiredMixin, ListView):
    """
    List all media files owned by the logged-in user.
    """
    model = Media
    template_name = "files.html"
    context_object_name = "media_list"

    def get_queryset(self):
        """
        Filter media by the current user.
        """
        return Media.objects.filter(owner=self.request.user)


class MediaDeleteView(LoginRequiredMixin, View):
    """
    Handle deletion of a media file owned by the user.
    """

    def post(self, request):
        """
        Deletes the media file after verifying ownership and existence.
        Cleans up the physical file from storage, then removes DB record.
        Returns updated media list partial for HTMX re-rendering.
        """
        try:
            media = Media.objects.get(pk=request.POST.get("pk"))
        except Media.DoesNotExist:
            response = HttpResponse("Media not found", status=404)
            response["HX-Retarget"] = "#error"
            response["HX-Reswap"] = "innerHTML"
            return response

        if media.owner != request.user:
            response = HttpResponse("You do not have permission to delete this media", status=403)
            response["HX-Retarget"] = "#error"
            response["HX-Reswap"] = "innerHTML"
            return response

        # Delete file from disk if exists
        if media.file and os.path.isfile(media.file.path):
            os.remove(media.file.path)

        # Delete DB record
        media.delete()

        # Return updated media list partial for client-side update
        response = render(
            request,
            "partials/files_rows.html",
            {"media_list": Media.objects.filter(owner=request.user)},
        )
        response["HX-Retarget"] = ".tbody"
        response["HX-Reswap"] = "outerHTML"
        return response


@login_required
def upload_media(request):
    """
    Handle media upload with encryption and save encrypted file and key.

    Steps:
    - Validate upload form.
    - Save uploaded file temporarily.
    - Encrypt the file using generated key.
    - Save encrypted file and encrypted key to Media model.
    - Clean up temporary files.
    - Redirect to media listing on success.

    Returns:
        Rendered upload form or HTMX redirect response.
    """
    if request.method == "POST":
        form = MediaUploadForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            file = request.FILES.get("file")

            # Initialize encryptor with master key
            encryptor = Encryptor(master_key=settings.ENCRYPTION_MASTER_KEY)

            # Generate raw key and encrypted key for storage
            raw_key, encrypted_key = encryptor.generate_secure_key()

            # Save uploaded file temporarily for encryption
            temp_input_path = f"/tmp/{uuid.uuid4()}_{file.name}"
            with open(temp_input_path, "wb") as temp_file:
                for chunk in file.chunks():
                    temp_file.write(chunk)

            temp_output_path = temp_input_path + ".sealed"

            # Encrypt the file using raw key
            encryptor.encrypt_file(temp_input_path, temp_output_path)

            with open(temp_output_path, "rb") as enc_file:
                encrypted_data = enc_file.read()

            media = form.save(commit=False)

            media.key = encrypted_key  # Store encrypted key in DB
            media.owner = request.user

            # Save encrypted file without committing DB save yet
            media.file.save(f"{file.name}.sealed", ContentFile(encrypted_data), save=False)

            media.save()
            form.save_m2m()

            # Clean up temp files
            os.remove(temp_input_path)
            os.remove(temp_output_path)

            # Use HTMX redirect header to reload media list page
            response = HttpResponse()
            response["HX-Redirect"] = "/dashboard/media"
            return response
    else:
        form = MediaUploadForm(user=request.user)
    return render(request, "partials/upload.html", {"form": form})


@login_required
def download_media(request, pk):
    """
    Securely decrypt and serve a media file to the user if they have access.

    Access allowed if:
    - User is the owner of the media.
    - User belongs to any group having access to the media.

    Decrypts the stored encrypted file on the fly,
    then sends the decrypted content as an HTTP attachment.

    Args:
        pk: Media primary key.

    Returns:
        HttpResponse with decrypted file or error.
    """
    media = get_object_or_404(Media, pk=pk)

    # Get Member IDs associated with the user to check group access
    member_ids = Member.objects.filter(user=request.user).values_list("id", flat=True)

    # Permission check
    if (
        request.user != media.owner
        and not media.groups.filter(members__id__in=member_ids).exists()
    ):
        return HttpResponse("You don't have permission to access this file", status=403)

    encrypted_file_path = media.file.path
    if not os.path.exists(encrypted_file_path):
        raise Http404("Encrypted file not found")

    original_filename = os.path.basename(media.file.name).replace(".sealed", "")
    decrypted_temp_path = f"/tmp/decrypted_{uuid.uuid4()}_{original_filename}"

    try:
        decryptor = Encryptor(key=media.key, master_key=settings.ENCRYPTION_MASTER_KEY)

        # Decrypt the file to a temp location and get decrypted content
        decrypted_data = decryptor.decrypt_file(encrypted_file_path, decrypted_temp_path)

        content_type = mimetypes.guess_type(original_filename)[0] or "application/octet-stream"

        response = HttpResponse(decrypted_data, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{original_filename}"'

        # Log the download activity
        ActivityLog.objects.create(
            actor=request.user,
            owner=media.owner,
            event_type="media_download",
            ip_address=get_client_ip(request),
            media=media,
            group=media.groups.first() if media.groups.exists() else None,
            additional_data={"file": media.name},
        )

        return response

    except Exception as e:
        # Handle any error during decryption or file serving
        return render(
            request,
            "error.html",
            {"error": "An error happened during file processing, please contact the support."},
            status=403,
        )
    finally:
        # Cleanup decrypted temp file if exists
        if os.path.exists(decrypted_temp_path):
            try:
                os.remove(decrypted_temp_path)
            except Exception as e:
                print(f"Failed to clean up temp file {decrypted_temp_path}: {str(e)}")


@login_required
def generate_preview_link(request, pk):
    """
    Generate a temporary preview link with one-time access key for a media file.

    The preview link expires in 6 hours.

    Returns:
        JSON response with shareable preview URL containing token and key.
    """
    media = get_object_or_404(Media, pk=pk, owner=request.user)

    token = secrets.token_urlsafe(24)
    key = secrets.token_urlsafe(32)

    preview_link = PreviewLink.objects.create(
        media=media,
        token=token,
        expires_at=timezone.now() + timedelta(hours=6),
    )
    OneTimeKey.objects.create(media=media, key=key)

    share_url = f"{request.build_absolute_uri('/')[:-1]}/media/preview/{token}?key={key}"
    return JsonResponse({"share_url": share_url})


def preview_file(request, token):
    """
    Render a media file preview if token and key are valid and not expired/used.

    Validates the one-time key without marking it as used.

    Returns:
        Rendered preview page or error page.
    """
    key_param = request.GET.get("key")
    preview = get_object_or_404(PreviewLink, token=token)

    if not preview.is_valid():
        return render(
            request,
            "error.html",
            {"error": "The link is either expired or used, please request a new one from the issuer."},
            status=403,
        )

    if not OneTimeKey.objects.filter(media=preview.media, key=key_param, used=False).exists():
        return render(
            request,
            "error.html",
            {"error": "The key is either invalid or used, please request a new link from the issuer."},
            status=403,
        )

    media = preview.media
    metadata = media.metadata or {}

    ActivityLog.objects.create(
        actor=request.user if request.user else None,
        owner=media.owner,
        event_type="media_preview",
        ip_address=get_client_ip(request),
        media=media,
        group=media.groups.first() if media.groups.exists() else None,
        additional_data={"file": media.name, "metadata": metadata, "token": token},
    )

    return render(
        request,
        "file_preview.html",
        {
            "media": media,
            "metadata": metadata,
            "token": token,
            "key": key_param,
        },
    )


def download_file(request, token):
    """
    Download a media file through a preview link with a one-time key.

    Marks the key as used after successful download.

    Returns:
        HttpResponse with decrypted file or error page.
    """
    key_param = request.GET.get("key")
    preview = get_object_or_404(PreviewLink, token=token)

    if not preview.is_valid():
        return render(
            request,
            "error.html",
            {"error": "The link is either expired or used, please request a new one from the issuer."},
            status=403,
        )

    try:
        one_time_key = OneTimeKey.objects.get(media=preview.media, key=key_param, used=False)
    except OneTimeKey.DoesNotExist:
        return render(
            request,
            "error.html",
            {"error": "The key is either invalid or used, please request a new link from the issuer."},
            status=403,
        )

    media = preview.media
    encrypted_file_path = media.file.path
    original_filename = os.path.basename(media.file.name).replace(".sealed", "")
    decrypted_temp_path = f"/tmp/decrypted_{uuid.uuid4()}_{original_filename}"

    try:
        decryptor = Encryptor(key=media.key, master_key=settings.ENCRYPTION_MASTER_KEY)
        decrypted_data = decryptor.decrypt_file(encrypted_file_path, decrypted_temp_path)

        content_type = mimetypes.guess_type(original_filename)[0] or "application/octet-stream"
        response = HttpResponse(decrypted_data, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{original_filename}"'

        one_time_key.used = True
        one_time_key.save()

        ActivityLog.objects.create(
            actor=request.user if request.user else None,
            owner=media.owner,
            event_type="media_download",
            ip_address=get_client_ip(request),
            media=media,
            group=media.groups.first() if media.groups.exists() else None,
            additional_data={"file": media.name},
        )
        return response
    except Exception as e:
        return render(
            request,
            "error.html",
            {"error": "The decryption failed due to internal server error, please contact the support."},
            status=500,
        )
    finally:
        if os.path.exists(decrypted_temp_path):
            os.remove(decrypted_temp_path)
