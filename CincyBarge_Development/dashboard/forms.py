from django import forms
from .models import Supplier


class FileUploadForm(forms.Form):
    """Form for uploading CSV or JSON files with unstructured inventory data"""
    supplier = forms.ModelChoiceField(
        queryset=Supplier.objects.all(),
        required=True,
        widget=forms.Select(attrs={'class': 'form-control'}),
        help_text="Select the supplier for this inventory data"
    )
    file = forms.FileField(
        required=True,
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.csv,.json'}),
        help_text="Upload a CSV or JSON file"
    )
    
    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            file_extension = file.name.split('.')[-1].lower()
            if file_extension not in ['csv', 'json']:
                raise forms.ValidationError("Only CSV and JSON files are allowed.")
        return file
