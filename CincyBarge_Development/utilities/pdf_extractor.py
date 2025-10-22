"""
PDF Extraction Utility for Bill of Lading
Uses pdfplumber to extract text and tables from BOL PDFs
"""
import pdfplumber
import re
from typing import Dict, List, Any, Optional
from decimal import Decimal
from datetime import datetime


class BOLPDFExtractor:
    """Extract and parse Bill of Lading data from PDF files"""
    
    def __init__(self, pdf_file):
        """
        Initialize the extractor with a PDF file
        
        Args:
            pdf_file: File object or path to PDF
        """
        self.pdf_file = pdf_file
        self.extracted_data = {}
        
    def extract_all(self) -> Dict[str, Any]:
        """
        Main method to extract all BOL data from PDF
        
        Returns:
            Dictionary containing all extracted BOL fields
        """
        try:
            with pdfplumber.open(self.pdf_file) as pdf:
                # Extract text from all pages
                full_text = ""
                tables = []
                
                for page in pdf.pages:
                    full_text += page.extract_text() or ""
                    page_tables = page.extract_tables()
                    if page_tables:
                        tables.extend(page_tables)
                
                # Parse the extracted text and tables
                self.extracted_data = self._parse_bol_data(full_text, tables)
                
                return self.extracted_data
                
        except Exception as e:
            raise Exception(f"Error extracting PDF data: {str(e)}")
    
    def _parse_bol_data(self, text: str, tables: List[List[List[str]]]) -> Dict[str, Any]:
        """
        Parse BOL data from extracted text and tables
        
        Args:
            text: Extracted text from PDF
            tables: Extracted tables from PDF
            
        Returns:
            Dictionary with parsed BOL fields
        """
        data = {
            'bill_number': self._extract_bill_number(text),
            'shipper_name': self._extract_shipper_name(text),
            'shipper_address': self._extract_shipper_address(text),
            'consignee_name': self._extract_consignee_name(text),
            'consignee_address': self._extract_consignee_address(text),
            'origin': self._extract_origin(text),
            'destination': self._extract_destination(text),
            'carrier': self._extract_carrier(text),
            'vessel_name': self._extract_vessel_name(text),
            'container_number': self._extract_container_number(text),
            'seal_number': self._extract_seal_number(text),
            'freight_charges': self._extract_freight_charges(text),
            'delivery_date': self._extract_delivery_date(text),
            'line_items': self._extract_line_items(tables, text),
            'notes': self._extract_notes(text),
        }
        
        # Remove None values
        return {k: v for k, v in data.items() if v is not None}
    
    def _extract_bill_number(self, text: str) -> Optional[str]:
        """Extract BOL number"""
        patterns = [
            r'(?:BOL|B/L|Bill of Lading)\s*(?:No\.?|Number|#)?\s*:?\s*([A-Z0-9-]+)',
            r'(?:Number|No\.?|#)\s*:?\s*([A-Z0-9-]+)',
            r'BOL[-\s]?(\d{6,})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_shipper_name(self, text: str) -> Optional[str]:
        """Extract shipper name"""
        patterns = [
            r'(?:Shipper|From|Consignor)\s*:?\s*\n?\s*([^\n]+)',
            r'Shipper[:\s]+([A-Za-z0-9\s,\.&-]+?)(?:\n|Address)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_shipper_address(self, text: str) -> Optional[str]:
        """Extract shipper address"""
        # Look for shipper section and extract address lines
        shipper_match = re.search(
            r'(?:Shipper|From)[:\s]+[^\n]+\n((?:[^\n]+\n){1,4})',
            text, 
            re.IGNORECASE
        )
        
        if shipper_match:
            address = shipper_match.group(1).strip()
            # Stop at next section header
            address = re.split(r'(?:Consignee|To|Carrier|Notify)', address, flags=re.IGNORECASE)[0]
            return address.strip()
        return None
    
    def _extract_consignee_name(self, text: str) -> Optional[str]:
        """Extract consignee name"""
        patterns = [
            r'(?:Consignee|To|Deliver To)\s*:?\s*\n?\s*([^\n]+)',
            r'Consignee[:\s]+([A-Za-z0-9\s,\.&-]+?)(?:\n|Address)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_consignee_address(self, text: str) -> Optional[str]:
        """Extract consignee address"""
        consignee_match = re.search(
            r'(?:Consignee|To)[:\s]+[^\n]+\n((?:[^\n]+\n){1,4})',
            text,
            re.IGNORECASE
        )
        
        if consignee_match:
            address = consignee_match.group(1).strip()
            # Stop at next section header
            address = re.split(r'(?:Notify|Carrier|Container|Vessel)', address, flags=re.IGNORECASE)[0]
            return address.strip()
        return None
    
    def _extract_origin(self, text: str) -> Optional[str]:
        """Extract origin/port of loading"""
        patterns = [
            r'(?:Origin|Port of Loading|From Port)\s*:?\s*([^\n]+)',
            r'(?:Loading Port|POL)\s*:?\s*([^\n]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_destination(self, text: str) -> Optional[str]:
        """Extract destination/port of discharge"""
        patterns = [
            r'(?:Destination|Port of Discharge|To Port)\s*:?\s*([^\n]+)',
            r'(?:Discharge Port|POD)\s*:?\s*([^\n]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_carrier(self, text: str) -> Optional[str]:
        """Extract carrier name"""
        patterns = [
            r'(?:Carrier|Shipping Line)\s*:?\s*([^\n]+)',
            r'Carrier[:\s]+([A-Za-z0-9\s,\.&-]+?)(?:\n|\s{2,})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_vessel_name(self, text: str) -> Optional[str]:
        """Extract vessel/barge name"""
        patterns = [
            r'(?:Vessel|Ship|Barge|Boat)\s*(?:Name)?\s*:?\s*([^\n]+)',
            r'Vessel[:\s]+([A-Za-z0-9\s-]+?)(?:\n|\s{2,})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_container_number(self, text: str) -> Optional[str]:
        """Extract container number"""
        patterns = [
            r'(?:Container|CNTR)\s*(?:No\.?|Number|#)?\s*:?\s*([A-Z]{4}\d{7})',
            r'Container[:\s]+([A-Z0-9-]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_seal_number(self, text: str) -> Optional[str]:
        """Extract seal number"""
        patterns = [
            r'(?:Seal|SEAL)\s*(?:No\.?|Number|#)?\s*:?\s*([A-Z0-9-]+)',
            r'Seal[:\s]+([A-Z0-9-]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_freight_charges(self, text: str) -> Optional[Decimal]:
        """Extract freight charges"""
        patterns = [
            r'(?:Freight|Charges?|Cost)\s*:?\s*\$?\s*([\d,]+\.?\d*)',
            r'Total\s+Freight\s*:?\s*\$?\s*([\d,]+\.?\d*)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                amount_str = match.group(1).replace(',', '')
                try:
                    return Decimal(amount_str)
                except:
                    pass
        return None
    
    def _extract_delivery_date(self, text: str) -> Optional[str]:
        """Extract delivery/expected arrival date"""
        patterns = [
            r'(?:Delivery|Arrival|ETA)\s+(?:Date)?\s*:?\s*(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
            r'(?:Expected|Est\.?)\s+(?:Delivery|Arrival)\s*:?\s*(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                date_str = match.group(1)
                # Try to parse and reformat to YYYY-MM-DD
                try:
                    for fmt in ['%m/%d/%Y', '%m-%d-%Y', '%d/%m/%Y', '%m/%d/%y']:
                        try:
                            date_obj = datetime.strptime(date_str, fmt)
                            return date_obj.strftime('%Y-%m-%d')
                        except ValueError:
                            continue
                except:
                    pass
                return date_str
        return None
    
    def _extract_line_items(self, tables: List[List[List[str]]], text: str) -> List[Dict[str, Any]]:
        """Extract line items from tables"""
        line_items = []
        
        if not tables:
            return line_items
        
        # Process each table
        for table in tables:
            if not table or len(table) < 2:
                continue
            
            # Identify header row (usually first row)
            headers = [h.lower() if h else '' for h in table[0]]
            
            # Find relevant column indices
            desc_col = self._find_column_index(headers, ['description', 'product', 'item', 'commodity'])
            qty_col = self._find_column_index(headers, ['quantity', 'qty', 'pieces', 'pcs'])
            weight_col = self._find_column_index(headers, ['weight', 'wt', 'gross weight', 'net weight'])
            
            # Extract data rows
            for row in table[1:]:
                if not row or not any(row):
                    continue
                
                item = {}
                
                # Extract description
                if desc_col is not None and desc_col < len(row):
                    item['description'] = row[desc_col].strip() if row[desc_col] else ''
                
                # Extract quantity
                if qty_col is not None and qty_col < len(row):
                    qty_str = row[qty_col].strip() if row[qty_col] else ''
                    try:
                        item['quantity'] = int(re.sub(r'[^\d]', '', qty_str))
                    except:
                        pass
                
                # Extract weight
                if weight_col is not None and weight_col < len(row):
                    weight_str = row[weight_col].strip() if row[weight_col] else ''
                    try:
                        weight_num = re.search(r'([\d,]+\.?\d*)', weight_str)
                        if weight_num:
                            item['weight'] = Decimal(weight_num.group(1).replace(',', ''))
                    except:
                        pass
                
                # Only add if we have at least description or quantity
                if item.get('description') or item.get('quantity'):
                    line_items.append(item)
        
        return line_items
    
    def _find_column_index(self, headers: List[str], keywords: List[str]) -> Optional[int]:
        """Find column index by matching keywords in headers"""
        for i, header in enumerate(headers):
            for keyword in keywords:
                if keyword in header:
                    return i
        return None
    
    def _extract_notes(self, text: str) -> Optional[str]:
        """Extract notes or special instructions"""
        patterns = [
            r'(?:Notes?|Remarks?|Instructions?|Special Instructions?)\s*:?\s*\n((?:[^\n]+\n?)+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                notes = match.group(1).strip()
                # Limit to reasonable length (first 500 chars)
                return notes[:500] if len(notes) > 500 else notes
        return None


def extract_bol_from_pdf(pdf_file) -> Dict[str, Any]:
    """
    Convenience function to extract BOL data from a PDF file
    
    Args:
        pdf_file: File object or path to PDF
        
    Returns:
        Dictionary containing extracted BOL data
    """
    extractor = BOLPDFExtractor(pdf_file)
    return extractor.extract_all()
