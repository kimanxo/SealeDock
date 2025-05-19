from django import forms
from django.core.exceptions import ValidationError
from .models import Media, Group

# Maximum allowed file size in megabytes
MAX_FILE_SIZE_MB = 25


class MediaUploadForm(forms.ModelForm):
    # Optional field to select multiple groups to share the media with
    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.none(),  # Populated in __init__ based on user
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
        # Extract user from kwargs and initialize form
        user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

        # Limit group choices to groups where the user is an admin or owner
        self.fields["groups"].queryset = Group.objects.filter(
            members__user=user, members__role__in=["admin", "owner"]
        )

    def clean_file(self):
        # Validate the uploaded file
        file = self.cleaned_data.get("file")
        if file:
            print(file.size)  # For debugging purposes
            if file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
                raise ValidationError(f"File exceeds {MAX_FILE_SIZE_MB} MB limit.")
        return file

    def clean(self):
        # Ensure 'name' defaults to the uploaded file name if not explicitly provided
        cleaned_data = super().clean()
        file = cleaned_data.get("file")
        name = cleaned_data.get("name")
        if not name and file:
            cleaned_data["name"] = file.name
        return cleaned_data


class GroupForm(forms.ModelForm):
    class Meta:
        model = Group
        fields = ['name']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'border border-gray-300 rounded px-2 py-1 w-full',
                'placeholder': 'Enter group name'
            }),
        }
