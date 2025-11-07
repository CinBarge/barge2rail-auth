from django import forms

from .models import (
    BillOfLading,
    BillOfLadingLineItem,
    BillOfLadingTemplate,
    Product,
    Supplier,
)


class FileUploadForm(forms.Form):
    """Form for uploading CSV or JSON files with unstructured inventory data"""

    supplier = forms.ModelChoiceField(
        queryset=Supplier.objects.all(),
        required=True,
        widget=forms.Select(attrs={"class": "form-control"}),
        help_text="Select the supplier for this inventory data",
    )
    file = forms.FileField(
        required=True,
        widget=forms.FileInput(attrs={"class": "form-control", "accept": ".csv,.json"}),
        help_text="Upload a CSV or JSON file",
    )

    def clean_file(self):
        file = self.cleaned_data.get("file")
        if file:
            file_extension = file.name.split(".")[-1].lower()
            if file_extension not in ["csv", "json"]:
                raise forms.ValidationError("Only CSV and JSON files are allowed.")
        return file


class BillOfLadingTemplateForm(forms.ModelForm):
    """Form for uploading BOL PDF templates"""

    class Meta:
        model = BillOfLadingTemplate
        fields = ["supplier", "template_file", "description"]
        widgets = {
            "supplier": forms.Select(attrs={"class": "form-control"}),
            "template_file": forms.FileInput(
                attrs={"class": "form-control", "accept": ".pdf"}
            ),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
        }

    def clean_template_file(self):
        file = self.cleaned_data.get("template_file")
        if file:
            file_extension = file.name.split(".")[-1].lower()
            if file_extension != "pdf":
                raise forms.ValidationError(
                    "Only PDF files are allowed for BOL templates."
                )

            # Check file size (max 10MB)
            if file.size > 10 * 1024 * 1024:
                raise forms.ValidationError("File size cannot exceed 10MB.")
        return file


class BillOfLadingForm(forms.ModelForm):
    """Form for creating/editing Bill of Lading"""

    class Meta:
        model = BillOfLading
        fields = [
            "supplier",
            "shipper_name",
            "shipper_address",
            "consignee_name",
            "consignee_address",
            "origin",
            "destination",
            "carrier",
            "vessel_name",
            "truck_number",
            "container_number",
            "seal_number",
            "freight_charges",
            "delivery_date",
            "notes",
        ]
        widgets = {
            "supplier": forms.Select(attrs={"class": "form-control"}),
            "shipper_name": forms.TextInput(attrs={"class": "form-control"}),
            "shipper_address": forms.Textarea(
                attrs={"class": "form-control", "rows": 2}
            ),
            "consignee_name": forms.TextInput(attrs={"class": "form-control"}),
            "consignee_address": forms.Textarea(
                attrs={"class": "form-control", "rows": 2}
            ),
            "origin": forms.TextInput(attrs={"class": "form-control"}),
            "destination": forms.TextInput(attrs={"class": "form-control"}),
            "carrier": forms.TextInput(attrs={"class": "form-control"}),
            "vessel_name": forms.TextInput(attrs={"class": "form-control"}),
            "truck_number": forms.TextInput(attrs={"class": "form-control"}),
            "container_number": forms.TextInput(attrs={"class": "form-control"}),
            "seal_number": forms.TextInput(attrs={"class": "form-control"}),
            "freight_charges": forms.NumberInput(
                attrs={"class": "form-control", "step": "0.01"}
            ),
            "delivery_date": forms.DateInput(
                attrs={"class": "form-control", "type": "date"}
            ),
            "notes": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
        }


class BillOfLadingLineItemForm(forms.ModelForm):
    """Form for adding products to BOL"""

    class Meta:
        model = BillOfLadingLineItem
        fields = ["product", "quantity", "weight", "description"]
        widgets = {
            "product": forms.Select(attrs={"class": "form-control"}),
            "quantity": forms.NumberInput(attrs={"class": "form-control", "min": "1"}),
            "weight": forms.NumberInput(
                attrs={"class": "form-control", "step": "0.01"}
            ),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
        }


class BOLPDFUploadForm(forms.Form):
    """Form for uploading BOL PDF for data extraction"""

    supplier = forms.ModelChoiceField(
        queryset=Supplier.objects.all(),
        required=True,
        widget=forms.Select(attrs={"class": "form-control"}),
        help_text="Select the supplier for this Bill of Lading",
    )
    pdf_file = forms.FileField(
        required=True,
        widget=forms.FileInput(attrs={"class": "form-control", "accept": ".pdf"}),
        help_text="Upload a Bill of Lading PDF to extract data",
    )

    def clean_pdf_file(self):
        file = self.cleaned_data.get("pdf_file")
        if file:
            file_extension = file.name.split(".")[-1].lower()
            if file_extension != "pdf":
                raise forms.ValidationError("Only PDF files are allowed.")

            # Check file size (max 15MB)
            if file.size > 15 * 1024 * 1024:
                raise forms.ValidationError("File size cannot exceed 15MB.")
        return file
