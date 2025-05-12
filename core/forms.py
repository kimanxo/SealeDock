from django import forms
from django.core.exceptions import ValidationError
from .models import Media, Group

MAX_FILE_SIZE_MB = 25


class MediaUploadForm(forms.ModelForm):
    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.none(),
        required=False,
        widget=forms.SelectMultiple,
        label="Share with Groups (optional)",
    )

    class Meta:
        model = Media
        fields = ["file", "name", "groups"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "default: filename "}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.fields["groups"].queryset = Group.objects.filter(
            members__user=user, members__role__in=["admin", "owner"]
        )

    def clean_file(self):
        file = self.cleaned_data.get("file")
        if file:
            print(file.size)
            if file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
                raise ValidationError(f"File exceeds {MAX_FILE_SIZE_MB} MB limit.")

        return file

    def clean(self):
        cleaned_data = super().clean()
        file = cleaned_data.get("file")
        name = cleaned_data.get("name")
        if not name and file:
            cleaned_data["name"] = file.name
        return cleaned_data
