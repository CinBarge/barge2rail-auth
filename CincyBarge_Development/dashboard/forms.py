from django import forms
from .models import Supplier, BillOfLading, BillOfLadingLineItem, Product


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


class BillOfLadingForm(forms.ModelForm):
    """Form for creating/editing Bill of Lading"""
    
    class Meta:
        model = BillOfLading
        fields = [
            'supplier', 'shipper_name', 'shipper_address', 'consignee_name', 
            'consignee_address', 'origin', 'destination', 'carrier', 
            'vessel_name', 'container_number', 'seal_number', 
            'delivery_date', 'notes'
        ]
        widgets = {
            'supplier': forms.Select(attrs={'class': 'form-control'}),
            'shipper_name': forms.TextInput(attrs={'class': 'form-control'}),
            'shipper_address': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'consignee_name': forms.TextInput(attrs={'class': 'form-control'}),
            'consignee_address': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'origin': forms.TextInput(attrs={'class': 'form-control'}),
            'destination': forms.TextInput(attrs={'class': 'form-control'}),
            'carrier': forms.TextInput(attrs={'class': 'form-control'}),
            'vessel_name': forms.TextInput(attrs={'class': 'form-control'}),
            'container_number': forms.TextInput(attrs={'class': 'form-control'}),
            'seal_number': forms.TextInput(attrs={'class': 'form-control'}),
            'delivery_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


class BillOfLadingLineItemForm(forms.ModelForm):
    """Form for adding products to BOL"""
    
    class Meta:
        model = BillOfLadingLineItem
        fields = ['product', 'quantity', 'weight', 'description']
        widgets = {
            'product': forms.Select(attrs={'class': 'form-control'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control', 'min': '1'}),
            'weight': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
        }
