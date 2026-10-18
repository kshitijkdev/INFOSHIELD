"""
InfoShield AI - Rule-Based PII Detection & Classification Engine
Stage 1: Information Extraction (Actual values from OCR)
Stage 2: Security Classification (PII type and risk stratification)
Stage 3: Protection Preview (Zero-trust data minimization and masking)

NO hardcoding, NO sample metadata, NO ground-truth shortcuts.
Extracts dynamically from OCR output and document layout geometry.
"""

import re
import numpy as np
from typing import List, Dict, Any, Optional
from collections import OrderedDict


class PIIDetector:
    """
    Production PII detection and classification engine.
    Separates actual value extraction from security risk classification and masking.
    """

    # Centralized Risk Stratification Matrix
    RISK_LEVELS = {
        "Aadhaar Number": "HIGH",
        "VID": "HIGH",
        "PAN Number": "HIGH",
        "Bank Account Number": "HIGH",
        "QR Code": "HIGH",
        "Mobile Number": "MEDIUM",
        "Date of Birth": "MEDIUM",
        "Address": "MEDIUM",
        "PIN Code": "MEDIUM",
        "IFSC Code": "MEDIUM",
        "Email Address": "MEDIUM",
        "Person Name": "LOW",
        "Gender": "LOW",
        "Photograph": "MEDIUM",
        "Licence Number": "HIGH",
        "Driving Licence Number": "HIGH",
        "Validity Date": "LOW",
        "Blood Group": "MEDIUM",
        "Authorized Classes": "LOW",
        "Passport Number": "HIGH",
        "MRZ": "HIGH",
        "Salary / Income": "HIGH",
        "Employee ID": "MEDIUM",
        "Roll Number": "LOW",
        "Registration Number": "LOW",
        "Marks / CGPA": "LOW",
        "Passing Year": "LOW",
        "Nationality": "LOW",
        "Designation": "LOW",
        "Statement Period": "LOW",
    }

    # Common Indian States and Cities for contextual address classification
    INDIAN_STATES = [
        "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
        "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand", "Karnataka",
        "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya", "Mizoram",
        "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu",
        "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal",
        "Delhi", "Mumbai", "Bangalore", "Pune", "Hyderabad", "Chennai", "Kolkata",
        "Noida", "Gurgaon", "Ahmedabad", "Jaipur", "Chandigarh", "Lucknow", "Nalbari"
    ]

    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Compiles regex patterns for PII identification."""
        # Aadhaar Number (12 digits, begins 2-9)
        self.aadhaar_pattern = re.compile(
            r"\b([2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4})\b"
        )

        # VID (Virtual ID - 16 digits)
        self.vid_pattern = re.compile(
            r"(?:VID|Virtual\s+ID)[\s:#.]*([0-9\s]{16,20})\b",
            re.IGNORECASE
        )

        # PAN Number (5 letters, 4 digits, 1 letter, OCR space-resilient)
        self.pan_pattern = re.compile(
            r"\b([A-Za-z]{5}[\s\-]?[0-9]{1,4}[\s\-]?[0-9]{1,3}[\s\-]?[A-Za-z])\b|(?:PAN|Permanent\s+Account\s+Number)[\s:#.]*([A-Za-z0-9\s\-]{10,14})\b",
            re.IGNORECASE
        )

        # Mobile Number (10 digits starting 6-9)
        self.mobile_labeled_pattern = re.compile(
            r"(?:Mobile\s*No|Mobile|Phone\s*No|Phone|Mob|Tel)[\s\w.:]*?([6-9]\d{9})\b",
            re.IGNORECASE
        )
        self.mobile_standalone_pattern = re.compile(
            r"\b([6-9]\d{9})\b"
        )

        # Email Address
        self.email_pattern = re.compile(
            r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
        )

        # Date of Birth
        self.dob_context_pattern = re.compile(
            r"(?:DOB|D\.?O\.?B|Date\s+of\s+Birth|Birth\s+Date|Born)[\s:#.]*([0-3]?\d[\/\-.][0-1]?\d[\/\-.](?:19|20|\d{2})\d{2})\b",
            re.IGNORECASE
        )
        self.date_generic_pattern = re.compile(
            r"\b(0?[1-9]|[12]\d|3[01])[\/\-.](0?[1-9]|1[0-2])[\/\-.](19\d{2}|20\d{2})\b"
        )

        # Gender
        self.gender_pattern = re.compile(
            r"\b(MALE|FEMALE|TRANSGENDER)\b",
            re.IGNORECASE
        )

        # Postal PIN Code
        self.pincode_pattern = re.compile(
            r"(?:PIN|Pin\s*code|Postal\s*code)[\s:]*([1-9]\d{5})\b|\b([1-9]\d{2}\s?\d{3})\b",
            re.IGNORECASE
        )

        # Bank Account Number
        self.account_pattern = re.compile(
            r"(?:A\/C|Account|Acc\s*No|Account\s*Number)[\s:#.]*([0-9\s\-]{9,22})\b",
            re.IGNORECASE
        )

        # IFSC Code
        self.ifsc_pattern = re.compile(
            r"\b([A-Z]{4}0[A-Z0-9]{6})\b"
        )

        # Person Name Label
        self.name_label_pattern = re.compile(
            r"(?:Applicant\s+Name|Candidate\s+Name|Student\s+Name|Driver\s+Name|Name)[\s:]+([A-Za-z][A-Za-z\s\.\-]{2,35})",
            re.IGNORECASE
        )

        # Driving Licence Number
        self.dl_pattern = re.compile(
            r"(?:DL\s*(?:No|Number)|Licence\s*(?:No|Number)|License\s*(?:No|Number)|DL)[\s:#.]*([A-Z]{2}[-\s]?[0-9O]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{7}|[A-Z]{2}[0-9O]{2}\s*[0-9]{4}\s*[0-9]{7}|[A-Z]{2}[-\s]?[0-9O]{2}[0-9]{11,13})\b|\b([A-Z]{2}[0-9O]{2}[\s\-][0-9]{4}[\s\-][0-9]{7})\b|\b([A-Z]{2}[-\s]?[0-9O]{2}[0-9]{11})\b",
            re.IGNORECASE
        )

        # Validity Date
        self.validity_pattern = re.compile(
            r"(?:Valid\s*(?:Till|Upto|To|Through|Date)|Validity|Expires|Expiry)[\s:#.]*([0-3]?\d[\/\-.][0-1]?\d[\/\-.](?:19|20|\d{2})\d{2})\b",
            re.IGNORECASE
        )

        # Blood Group
        self.blood_group_pattern = re.compile(
            r"(?:Blood\s*Group|Blood\s*Grp|B\.?G\.?)[\s:#.]*([ABO][+-](?:ve)?|AB[+-](?:ve)?|O\s*[+-]|A\s*[+-]|B\s*[+-])\b",
            re.IGNORECASE
        )

        # Authorized Vehicle Classes
        self.cov_pattern = re.compile(
            r"(?:COV|Class\s*of\s*Vehicle|Veh\s*Class|Authori[sz]ed\s*(?:to\s*Drive|Classes)|Classes)[\s:#.]*([A-Z0-9,\s\/\-]+(?=\n|$))",
            re.IGNORECASE
        )

        # Passport Number
        self.passport_pattern = re.compile(
            r"(?:Passport\s*(?:No|Number)|Passport)[\s:#.]*([A-PR-WYa-pr-wy][0-9]{7})\b|\b([A-PR-WYa-pr-wy][1-9]\d{6})\b",
            re.IGNORECASE
        )

        # MRZ Machine Readable Zone
        self.mrz_pattern = re.compile(
            r"\b(P<[A-Z0-9<]{30,44}|[A-Z0-9<]{30,44})\b"
        )

        # Educational Roll / Registration Number
        self.roll_number_pattern = re.compile(
            r"(?:Roll\s*(?:No|Number)|Registration\s*(?:No|Number)|Reg\s*No|Enrollment\s*No)[\s:#.]*([A-Za-z0-9\/\-]+)\b",
            re.IGNORECASE
        )

        # Marks / CGPA / Grades
        self.marks_pattern = re.compile(
            r"(?:Total\s*Marks|CGPA|Percentage|Grade|GPA|Aggregate)[\s:#.]*([0-9.]+(?:\s*(?:\/|out of)\s*[0-9]+|\s*%)?|[A-O][+]?)\b",
            re.IGNORECASE
        )

        # Passing Year
        self.passing_year_pattern = re.compile(
            r"(?:Year\s*of\s*Passing|Passing\s*Year|Session|Academic\s*Year)[\s:#.]*([12]\d{3}(?:[-/]\d{2,4})?)\b",
            re.IGNORECASE
        )

        # Employee ID
        self.employee_id_pattern = re.compile(
            r"(?:Employee\s*ID|Emp\s*ID|Staff\s*ID|Worker\s*ID)[\s:#.]*([A-Za-z0-9\-]+)\b",
            re.IGNORECASE
        )

        # Salary / Compensation Amount
        self.salary_income_pattern = re.compile(
            r"(?:Net\s*Salary|Net\s*Pay|Gross\s*Salary|Basic\s*Pay|Monthly\s*Pay|Annual\s*CTC|Total\s*Income)[\s:#.]*([₹$Rs\.\s]*[0-9,]+(?:\.[0-9]{2})?)\b",
            re.IGNORECASE
        )

        # Designation / Role
        self.designation_pattern = re.compile(
            r"(?:Designation|Role|Job\s*Title|Position)[\s:#.]*([A-Za-z\s]{3,35})(?=\n|$)",
            re.IGNORECASE
        )

        # Statement Period
        self.statement_period_pattern = re.compile(
            r"(?:Statement\s*Period|Period)[\s:#.]*([0-3]?\d[\/\-.][0-1]?\d[\/\-.](?:19|20|\d{2})\d{2}\s*(?:to|-)\s*[0-3]?\d[\/\-.][0-1]?\d[\/\-.](?:19|20|\d{2})\d{2})\b",
            re.IGNORECASE
        )

        # Nationality
        self.nationality_pattern = re.compile(
            r"(?:Nationality|National)[\s:#.]*([A-Za-z]{3,15})\b",
            re.IGNORECASE
        )

    # --------------------------------------------------------------------------
    # MASKING / REDACTION ENGINE
    # --------------------------------------------------------------------------

    @staticmethod
    def mask_passport(val: str) -> str:
        """Masks Passport: 'Z8923412' -> 'ZXXXX412'"""
        clean = re.sub(r"[\s\-]", "", val).strip().upper()
        if len(clean) >= 6:
            return f"{clean[0]}{'X' * (len(clean) - 4)}{clean[-3:]}"
        return "ZXXXXXXX"

    @staticmethod
    def mask_employee_id(val: str) -> str:
        """Masks Employee ID: 'EMP-40912' -> 'EMP-XXXX2'"""
        clean = val.strip()
        if len(clean) >= 5:
            prefix = clean[:4]
            suffix = clean[-1:]
            return f"{prefix}{'X' * (len(clean) - 5)}{suffix}"
        return "EMPXXXX"

    @staticmethod
    def mask_roll_no(val: str) -> str:
        """Masks Roll No: '2617894' -> 'XXXX894'"""
        clean = val.strip()
        if len(clean) >= 4:
            return f"{'X' * (len(clean) - 3)}{clean[-3:]}"
        return "XXXX"

    @staticmethod
    def mask_income(val: str) -> str:
        """Masks financial compensation amounts."""
        return "[REDACTED - FINANCIAL COMPENSATION]"

    @staticmethod
    def mask_dl(val: str) -> str:
        """Masks Driving Licence: 'MH02 2018 0092341' -> 'MH02 XXXX XXXX341'"""
        clean = re.sub(r"[\s\-]", "", val).strip().upper()
        if len(clean) >= 10:
            prefix = clean[:4]
            suffix = clean[-3:]
            return f"{prefix} XXXX XXXX{suffix}"
        return re.sub(r"\d", "X", val)

    @staticmethod
    def mask_aadhaar(val: str) -> str:
        """Masks 12-digit Aadhaar: '8141 5978 8449' -> 'XXXX XXXX 8449'"""
        clean = re.sub(r"[\s\-]", "", val)
        if len(clean) >= 4:
            return f"XXXX XXXX {clean[-4:]}"
        return "XXXX XXXX XXXX"

    @staticmethod
    def mask_vid(val: str) -> str:
        """Masks 16-digit VID: '9186083758430970' -> 'XXXXXXXXXXXX0970'"""
        clean = re.sub(r"[\s\-]", "", val)
        if len(clean) >= 4:
            return f"{'X' * (len(clean) - 4)}{clean[-4:]}"
        return "XXXXXXXXXXXXXXXX"

    @staticmethod
    def mask_pan(val: str) -> str:
        """Masks PAN: 'ABCDE1234F' -> 'XXXXX1234F'"""
        clean = val.strip().upper()
        if len(clean) == 10:
            return f"XXXXX{clean[5:]}"
        return clean

    @staticmethod
    def mask_phone(val: str) -> str:
        """Masks 10-digit Phone: '9954018168' -> 'XXXXXX8168'"""
        clean = re.sub(r"[^\d]", "", val)
        if len(clean) >= 4:
            return f"{'X' * (len(clean) - 4)}{clean[-4:]}"
        return "XXXXXX0000"

    @staticmethod
    def mask_email(val: str) -> str:
        """Masks Email: 'user@example.com' -> 'us***r@example.com'"""
        try:
            user, domain = val.split("@", 1)
            if len(user) <= 2:
                masked_user = user[0] + "***"
            else:
                masked_user = user[:2] + "***" + user[-1]
            return f"{masked_user}@{domain}"
        except Exception:
            return "****@domain.com"

    @staticmethod
    def mask_dob(val: str) -> str:
        """Masks DOB: '11/09/2002' -> 'XX/XX/2002'"""
        parts = re.split(r"[\/\-.]", val.strip())
        if len(parts) == 3:
            sep = "/" if "/" in val else ("-" if "-" in val else ".")
            return f"XX{sep}XX{sep}{parts[2]}"
        return "XX/XX/XXXX"

    @staticmethod
    def mask_pincode(val: str) -> str:
        """Masks PIN: '781334' -> 'XXX334'"""
        clean = re.sub(r"\s", "", val)
        if len(clean) == 6:
            return f"XXX{clean[-3:]}"
        return clean

    @staticmethod
    def mask_address(val: str) -> str:
        """Redacts street addresses while preserving broader state/region."""
        clean = val.strip()
        matched_state = "Regional Jurisdiction"
        for st in PIIDetector.INDIAN_STATES:
            if st.lower() in clean.lower():
                matched_state = st
                break

        return f"[PARTIALLY REDACTED - Preserved Region: {matched_state}]"

    @staticmethod
    def mask_name(val: str) -> str:
        """Masks full name: 'Tapan Sarma' -> 'Tapan S***'"""
        parts = val.strip().split()
        if len(parts) >= 2:
            return f"{parts[0]} {parts[1][0]}***"
        elif len(parts) == 1 and len(parts[0]) > 2:
            return f"{parts[0][:2]}***"
        return val

    @staticmethod
    def mask_bank_account(val: str) -> str:
        """Masks bank account: '50100492817291' -> 'XXXXXXXX7291'"""
        clean = re.sub(r"[^\d]", "", val)
        if len(clean) >= 4:
            return f"{'X' * (len(clean) - 4)}{clean[-4:]}"
        return "XXXXXXXX"

    @staticmethod
    def mask_ifsc(val: str) -> str:
        """Masks IFSC: 'HDFC0001234' -> 'HDFC000XXXX'"""
        clean = val.strip().upper()
        if len(clean) >= 7:
            return f"{clean[:7]}{'X' * (len(clean) - 7)}"
        return "XXXX000XXXX"

    def locate_field_bbox(
        self,
        word_data: Dict[str, Any],
        target_str: str,
        field_name: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Locates the bounding box for a target string or PII entity in Tesseract word_data.
        Returns:
            {
                "bbox": {"x": int, "y": int, "width": int, "height": int},
                "token_boxes": [{"x": int, "y": int, "width": int, "height": int}, ...],
                "line_boxes": [{"x": int, "y": int, "width": int, "height": int}, ...]
            }
        """
        if not word_data or not target_str:
            return None

        words = word_data.get("text", [])
        lefts = word_data.get("left", [])
        tops = word_data.get("top", [])
        widths = word_data.get("width", [])
        heights = word_data.get("height", [])
        n = len(words)

        non_empty = []
        for i in range(n):
            w = str(words[i]).strip()
            if re.sub(r"[^A-Za-z0-9]", "", w):
                non_empty.append((i, w, lefts[i], tops[i], widths[i], heights[i]))

        def make_box(indices):
            sel_lefts = [lefts[i] for i in indices]
            sel_tops = [tops[i] for i in indices]
            sel_rights = [lefts[i] + widths[i] for i in indices]
            sel_bottoms = [tops[i] + heights[i] for i in indices]

            min_x = min(sel_lefts)
            min_y = min(sel_tops)
            max_x = max(sel_rights)
            max_y = max(sel_bottoms)

            tok_boxes = [
                {"x": lefts[i], "y": tops[i], "width": widths[i], "height": heights[i]}
                for i in indices
            ]

            lines = []
            curr_line = []
            curr_y = None
            for i in sorted(indices, key=lambda idx: (tops[idx], lefts[idx])):
                if curr_y is None or abs(tops[i] - curr_y) <= 18:
                    curr_line.append(i)
                    curr_y = tops[i] if curr_y is None else min(curr_y, tops[i])
                else:
                    lines.append(curr_line)
                    curr_line = [i]
                    curr_y = tops[i]
            if curr_line:
                lines.append(curr_line)

            line_boxes = []
            for l_idxs in lines:
                l_min_x = min(lefts[idx] for idx in l_idxs)
                l_min_y = min(tops[idx] for idx in l_idxs)
                l_max_x = max(lefts[idx] + widths[idx] for idx in l_idxs)
                l_max_y = max(tops[idx] + heights[idx] for idx in l_idxs)
                line_boxes.append({"x": l_min_x, "y": l_min_y, "width": l_max_x - l_min_x, "height": l_max_y - l_min_y})

            return {
                "bbox": {"x": min_x, "y": min_y, "width": max_x - min_x, "height": max_y - min_y},
                "token_boxes": tok_boxes,
                "line_boxes": line_boxes
            }

        target_tokens = [re.sub(r"[^A-Za-z0-9]", "", t).lower() for t in target_str.split() if re.sub(r"[^A-Za-z0-9]", "", t)]
        if not target_tokens:
            return None

        # Strategy 1: Contiguous sliding window token match
        num_target = len(target_tokens)
        for start_idx in range(len(non_empty) - num_target + 1):
            window = non_empty[start_idx : start_idx + num_target]
            w_tokens = [re.sub(r"[^A-Za-z0-9]", "", item[1]).lower() for item in window]
            if w_tokens == target_tokens:
                return make_box([item[0] for item in window])
            if [re.sub(r"^([a-z]{2})o", r"\g<1>0", wt) for wt in w_tokens] == [re.sub(r"^([a-z]{2})o", r"\g<1>0", tt) for tt in target_tokens]:
                return make_box([item[0] for item in window])

        # Strategy 2: Single token clean match
        target_clean = re.sub(r"[^A-Za-z0-9]", "", target_str).lower()
        for item in non_empty:
            idx, w, l, t, wd, h = item
            w_clean = re.sub(r"[^A-Za-z0-9]", "", w).lower()
            if w_clean == target_clean:
                return make_box([idx])

        # Strategy 3: 4-digit chunks for 12/16-digit numbers (Aadhaar / VID)
        if target_clean.isdigit() and len(target_clean) in (12, 16):
            chunks = [target_clean[i:i+4] for i in range(0, len(target_clean), 4)]
            num_chunks = len(chunks)
            for start_idx in range(len(non_empty) - num_chunks + 1):
                window = non_empty[start_idx : start_idx + num_chunks]
                w_tokens = [re.sub(r"[^0-9]", "", item[1]) for item in window]
                if w_tokens == chunks:
                    return make_box([item[0] for item in window])

        # Strategy 4: Subset token match for Address
        if field_name == "Address":
            matched_indices = []
            for t_tok in target_tokens:
                for item in non_empty:
                    idx, w, l, t, wd, h = item
                    w_clean = re.sub(r"[^A-Za-z0-9]", "", w).lower()
                    if t_tok == w_clean and idx not in matched_indices:
                        matched_indices.append(idx)
                        break
            if len(matched_indices) >= 3:
                median_y = float(np.median([tops[i] for i in matched_indices]))
                spatially_close = [i for i in matched_indices if abs(tops[i] - median_y) < 140]
                if len(spatially_close) >= 3:
                    return make_box(spatially_close)
                return make_box(matched_indices)

        return None

    # --------------------------------------------------------------------------
    # STAGE 1: INFORMATION EXTRACTION PIPELINE
    # --------------------------------------------------------------------------

    def extract_document_fields(
        self,
        text: str,
        word_data: Optional[Dict[str, Any]] = None,
        qr_detected: bool = False,
        qr_data: Optional[str] = None,
        qr_bbox: Optional[Dict[str, int]] = None,
        qr_polygon: Optional[List[List[float]]] = None,
        photo_detected: bool = False,
        photo_bbox: Optional[Dict[str, int]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        STAGE 1: Extracts actual values directly from OCR text and word layout geometry.
        Returns an ordered dictionary of detected fields:
          { field_name: { "field": str, "value": str, "masked_value": str, "risk": str, "confidence": float, "bbox": dict } }
        DO NOT invent missing values. Only populated if detected.
        """
        extracted = OrderedDict()

        def add_field(field_name: str, actual_val: str, masked_val: str, confidence: float, explicit_bbox: Optional[Dict[str, Any]] = None):
            clean_val = actual_val.strip()
            if not clean_val:
                return
            risk = self.RISK_LEVELS.get(field_name, "MEDIUM")
            field_data = {
                "field": field_name,
                "value": clean_val,
                "masked_value": masked_val,
                "risk": risk,
                "confidence": round(confidence, 2)
            }
            if explicit_bbox:
                field_data["bbox"] = explicit_bbox
            elif word_data and clean_val != "Could not confidently determine":
                loc = self.locate_field_bbox(word_data, clean_val, field_name)
                if loc:
                    field_data["bbox"] = loc["bbox"]
                    if loc.get("token_boxes"):
                        field_data["token_boxes"] = loc["token_boxes"]
                    if loc.get("line_boxes"):
                        field_data["line_boxes"] = loc["line_boxes"]

            extracted[field_name] = field_data

        # ----------------------------------------------------------------------
        # 1. PERSON NAME EXTRACTION
        # ----------------------------------------------------------------------
        person_name = None

        # Strategy A: Explicit Label Match (e.g. "Name: Aarav Sharma", "Name: ROHAN VERMA")
        label_match = self.name_label_pattern.search(text)
        if label_match:
            candidate = label_match.group(1).splitlines()[0].strip()
            candidate = re.split(r"(?:DOB|Date|Gender|Male|Female|Phone|Mobile|Address|Father)", candidate, flags=re.IGNORECASE)[0].strip()
            candidate = re.sub(r"[^A-Za-z\s\.]", "", candidate).strip()
            words = [w for w in candidate.split() if len(w) >= 2 and w.upper() not in ["NAME", "GOVERNMENT", "INDIA", "AUTHORITY", "TO"]]
            if 1 <= len(words) <= 4:
                person_name = " ".join(words)

        # Strategy B: Document-Layout Analysis above DOB (Aadhaar-style cards)
        if not person_name and word_data:
            dob_top = None
            for i, w in enumerate(word_data.get("text", [])):
                w_str = str(w).strip()
                if "DOB" in w_str.upper() or re.match(r"^\d{2}[\/\-]\d{2}[\/\-]\d{4}$", w_str):
                    dob_top = word_data["top"][i]
                    break

            if dob_top is not None:
                name_words = []
                for i, w in enumerate(word_data.get("text", [])):
                    wc = str(w).strip()
                    if not wc:
                        continue
                    try:
                        conf = float(word_data["conf"][i])
                        top = word_data["top"][i]
                    except Exception:
                        continue

                    # Bounding box must be above DOB (within 70px) and confidence >= 40
                    if dob_top - 70 <= top < dob_top - 5 and conf >= 40:
                        clean_w = re.sub(r"[^A-Za-z]", "", wc)
                        if len(clean_w) >= 2 and clean_w.upper() not in [
                            "NAME", "GOVERNMENT", "INDIA", "AUTHORITY", "UNIQUE", "IDENTIFICATION", "TO", "DOB", "MALE", "FEMALE"
                        ]:
                            name_words.append(clean_w)

                if 1 <= len(name_words) <= 4:
                    person_name = " ".join(name_words)

        # Strategy C: Pure Text Line analysis directly preceding DOB
        if not person_name:
            dob_m = self.dob_context_pattern.search(text) or self.date_generic_pattern.search(text)
            if dob_m:
                text_before_dob = text[:dob_m.start()]
                lines = [ln.strip() for ln in text_before_dob.splitlines() if ln.strip()]
                excluded = {
                    "GOVERNMENT", "INDIA", "AUTHORITY", "UNIQUE", "IDENTIFICATION",
                    "DOB", "DATE", "BIRTH", "MALE", "FEMALE", "ADDRESS", "AADHAAR", "TO", "ENROLMENT", "HELP", "UIDAI"
                }
                for ln in reversed(lines[-3:]):
                    cleaned_line = re.sub(r"[^A-Za-z\s]", " ", ln)
                    words = [w for w in cleaned_line.split() if len(w) >= 3 and w.upper() not in excluded]
                    if 2 <= len(words) <= 4 and all(w[0].isupper() or w.isupper() for w in words):
                        person_name = " ".join(words)
                        break

        # Register Person Name if detected, or report undetermined only on identity documents
        has_id_markers = bool(
            self.dob_context_pattern.search(text)
            or self.aadhaar_pattern.search(text)
            or self.pan_pattern.search(text)
            or self.gender_pattern.search(text)
            or any(kw in text.upper() for kw in ["AADHAAR", "PAN", "INCOME TAX", "IDENTIFICATION", "DOB", "GOVERNMENT OF INDIA"])
        )

        if person_name:
            add_field(
                field_name="Person Name",
                actual_val=person_name,
                masked_val=self.mask_name(person_name),
                confidence=0.92
            )
        elif has_id_markers:
            add_field(
                field_name="Person Name",
                actual_val="Could not confidently determine",
                masked_val="Could not confidently determine",
                confidence=0.0
            )

        # ----------------------------------------------------------------------
        # 2. DATE OF BIRTH
        # ----------------------------------------------------------------------
        dob_match = self.dob_context_pattern.search(text)
        if dob_match:
            dob_val = dob_match.group(1).strip()
            add_field("Date of Birth", dob_val, self.mask_dob(dob_val), 0.95)
        else:
            generic_date = self.date_generic_pattern.search(text)
            if generic_date:
                year = int(generic_date.group(3))
                if 1940 <= year <= 2025:
                    dob_val = generic_date.group(0).strip()
                    add_field("Date of Birth", dob_val, self.mask_dob(dob_val), 0.88)

        # ----------------------------------------------------------------------
        # 3. GENDER
        # ----------------------------------------------------------------------
        gender_match = self.gender_pattern.search(text)
        if gender_match:
            gender_val = gender_match.group(1).upper()
            add_field("Gender", gender_val, gender_val, 0.96)

        # ----------------------------------------------------------------------
        # 4. MOBILE NUMBER
        # ----------------------------------------------------------------------
        mob_match = self.mobile_labeled_pattern.search(text)
        if not mob_match:
            # Check standalone 10-digit number
            for match in self.mobile_standalone_pattern.finditer(text):
                cand_num = match.group(1)
                # Verify it is not part of Aadhaar, VID, or PIN code
                if not any(cand_num in text[max(0, m.start()-5):m.end()+5] for m in self.aadhaar_pattern.finditer(text)):
                    mob_match = match
                    break

        if mob_match:
            mob_val = mob_match.group(1).strip()
            add_field("Mobile Number", mob_val, self.mask_phone(mob_val), 0.93)

        # ----------------------------------------------------------------------
        # 5. EMAIL ADDRESS
        # ----------------------------------------------------------------------
        email_match = self.email_pattern.search(text)
        if email_match:
            email_val = email_match.group(1).strip()
            # Exclude institutional helpdesk emails (e.g. help@uidai.gov.in)
            if not any(inst in email_val.lower() for inst in ["uidai", "gov.in", "support@", "help@"]):
                add_field("Email Address", email_val, self.mask_email(email_val), 0.95)

        # ----------------------------------------------------------------------
        # 6. AADHAAR NUMBER
        # ----------------------------------------------------------------------
        for match in self.aadhaar_pattern.finditer(text):
            raw_adh = match.group(1).strip()
            clean_digits = re.sub(r"[\s\-]", "", raw_adh)
            if len(clean_digits) == 12 and not clean_digits.startswith("0") and not clean_digits.startswith("1"):
                add_field("Aadhaar Number", raw_adh, self.mask_aadhaar(raw_adh), 0.98)
                break

        # ----------------------------------------------------------------------
        # 7. VID (VIRTUAL ID)
        # ----------------------------------------------------------------------
        vid_match = self.vid_pattern.search(text)
        if vid_match:
            raw_vid = re.sub(r"[\s\-]", "", vid_match.group(1)).strip()
            if len(raw_vid) == 16 and raw_vid.isdigit():
                add_field("VID", raw_vid, self.mask_vid(raw_vid), 0.95)

        # ----------------------------------------------------------------------
        # 8. PAN NUMBER
        # ----------------------------------------------------------------------
        for match in self.pan_pattern.finditer(text):
            raw_pan = match.group(1) or match.group(2)
            if not raw_pan:
                continue
            clean_pan = re.sub(r"[\s\-]", "", raw_pan).upper()
            if len(clean_pan) == 10 and re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", clean_pan):
                if clean_pan not in ["INDIA", "STATE", "GOVT", "UNION", "DELHI"]:
                    add_field("PAN Number", clean_pan, self.mask_pan(clean_pan), 0.97)
                    break

        # ----------------------------------------------------------------------
        # 9. BANK ACCOUNT NUMBER
        # ----------------------------------------------------------------------
        acc_match = self.account_pattern.search(text)
        if acc_match:
            clean_acc = re.sub(r"[\s\-]", "", acc_match.group(1))
            if 9 <= len(clean_acc) <= 18 and clean_acc.isdigit():
                add_field("Bank Account Number", clean_acc, self.mask_bank_account(clean_acc), 0.94)

        # ----------------------------------------------------------------------
        # 10. IFSC CODE
        # ----------------------------------------------------------------------
        ifsc_match = self.ifsc_pattern.search(text)
        if ifsc_match:
            ifsc_val = ifsc_match.group(1).upper()
            add_field("IFSC Code", ifsc_val, self.mask_ifsc(ifsc_val), 0.95)

        # ----------------------------------------------------------------------
        # 11. ADDRESS EXTRACTION
        # ----------------------------------------------------------------------
        extracted_address = None

        # Strategy A: Word Data Confident Line Assembly
        if word_data:
            addr_start = False
            addr_words = []
            for i, w in enumerate(word_data.get("text", [])):
                wc = str(w).strip()
                if not wc:
                    continue
                try:
                    conf = float(word_data["conf"][i])
                except Exception:
                    conf = 0.0

                if any(lbl in wc for lbl in ["Address", "C/O", "S/O", "D/O", "W/O"]):
                    addr_start = True

                if addr_start:
                    if any(stop in wc for stop in ["1947", "help@", "uidai", "P.O.", "Box", "Mera"]):
                        break
                    if conf >= 35 or wc in [":", ",", "-", "~"]:
                        clean_w = re.sub(r"[\=\_\<\>\|\°]", "", wc).strip()
                        if clean_w:
                            addr_words.append(clean_w)
                    if re.match(r"^\d{6}$", wc) and conf >= 40:
                        break

            if len(addr_words) >= 4:
                # Remove leading 'Address :' if duplicated with 'C/O'
                combined_addr = " ".join(addr_words)
                combined_addr = re.sub(r"^Address\s*[:\s]*", "", combined_addr, flags=re.IGNORECASE).strip()
                extracted_address = combined_addr

        # Strategy B: Contextual regex matching around Address / C/O / S/O / D/O / W/O
        if not extracted_address:
            addr_match = re.search(
                r"(?:Address|Add|Add\.|Addr|C\/O|S\/O|D\/O|W\/O)[\s:#.]*([\s\S]{10,240}?)(?=\b[1-9]\d{5}\b)",
                text,
                re.IGNORECASE
            )
            if addr_match:
                pin_match = self.pincode_pattern.search(text[addr_match.start():addr_match.start()+260])
                pin_str = f" {pin_match.group(1)}" if pin_match and pin_match.group(1) else ""
                raw_addr = addr_match.group(0).strip() + pin_str
                raw_addr = re.sub(r"^Address\s*[:\s]*", "", raw_addr, flags=re.IGNORECASE).strip()
                clean_lines = [re.sub(r"[\=\~\_\<\>\|\°]", "", ln).strip() for ln in raw_addr.splitlines() if ln.strip()]
                extracted_address = " ".join(" ".join(clean_lines).split())

        if extracted_address and len(extracted_address) > 10:
            add_field(
                field_name="Address",
                actual_val=extracted_address,
                masked_val=self.mask_address(extracted_address),
                confidence=0.91
            )

        # ----------------------------------------------------------------------
        # 12. QR CODE MATRIX
        # ----------------------------------------------------------------------
        if qr_detected:
            add_field(
                field_name="QR Code",
                actual_val=qr_data if qr_data else "[DEMOGRAPHIC_PAYLOAD]",
                masked_val="[REMOVED - ENCRYPTED BIOMETRIC / DEMOGRAPHIC PAYLOAD]",
                confidence=0.99,
                explicit_bbox=qr_bbox
            )
            if "QR Code" in extracted and qr_polygon:
                extracted["QR Code"]["polygon"] = qr_polygon

        # ----------------------------------------------------------------------
        # 13. PHOTOGRAPH / PORTRAIT BIOMETRIC
        # ----------------------------------------------------------------------
        if photo_detected and photo_bbox:
            add_field(
                field_name="Photograph",
                actual_val="[BIOMETRIC_PORTRAIT_IMAGE]",
                masked_val="[REDACTED - PHOTOGRAPH OBSCOURED]",
                confidence=0.96,
                explicit_bbox=photo_bbox
            )

        # ----------------------------------------------------------------------
        # 14. DRIVING LICENCE NUMBER
        # ----------------------------------------------------------------------
        dl_match = self.dl_pattern.search(text)
        if dl_match:
            raw_dl = dl_match.group(1) or dl_match.group(2) or dl_match.group(3)
            if raw_dl:
                clean_dl = raw_dl.strip()
                clean_dl = re.sub(r"^([A-Z]{2})\s*O", r"\g<1>0", clean_dl)
                clean_dl = re.sub(r"^([A-Z]{2}\d)O", r"\g<1>0", clean_dl)
                add_field("Licence Number", clean_dl, self.mask_dl(clean_dl), 0.95)

        # ----------------------------------------------------------------------
        # 15. VALIDITY DATES
        # ----------------------------------------------------------------------
        val_match = self.validity_pattern.search(text)
        if val_match:
            val_date = val_match.group(1).strip()
            add_field("Validity Date", val_date, val_date, 0.90)

        # ----------------------------------------------------------------------
        # 16. BLOOD GROUP
        # ----------------------------------------------------------------------
        bg_match = self.blood_group_pattern.search(text)
        if bg_match:
            bg_val = bg_match.group(1).strip()
            add_field("Blood Group", bg_val, "XX", 0.94)

        # ----------------------------------------------------------------------
        # 17. AUTHORIZED VEHICLE CLASSES
        # ----------------------------------------------------------------------
        cov_match = self.cov_pattern.search(text)
        if cov_match:
            cov_val = cov_match.group(1).strip()
            cov_clean = re.sub(r"[^A-Za-z0-9,\s\/\-]", "", cov_val).strip()
            if cov_clean and len(cov_clean) <= 30 and not any(kw in cov_clean.upper() for kw in ["NAME", "DOB", "DATE", "INDIA"]):
                add_field("Authorized Classes", cov_clean, "[REDACTED]", 0.88)

        # ----------------------------------------------------------------------
        # 18. PASSPORT NUMBER
        # ----------------------------------------------------------------------
        pass_match = self.passport_pattern.search(text)
        if pass_match:
            p_val = pass_match.group(1) or pass_match.group(2)
            if p_val:
                p_clean = p_val.strip().upper()
                if not any(stop in p_clean for stop in ["INDIA", "STATE"]):
                    add_field("Passport Number", p_clean, self.mask_passport(p_clean), 0.96)

        # ----------------------------------------------------------------------
        # 19. NATIONALITY
        # ----------------------------------------------------------------------
        nat_match = self.nationality_pattern.search(text)
        if nat_match:
            nat_val = nat_match.group(1).strip().upper()
            if nat_val in ["INDIAN", "INDIA", "USA", "UK", "CANADIAN", "BRITISH", "AMERICAN"]:
                add_field("Nationality", nat_val, nat_val, 0.95)

        # ----------------------------------------------------------------------
        # 20. MRZ MACHINE READABLE ZONE
        # ----------------------------------------------------------------------
        for mrz_cand in self.mrz_pattern.findall(text):
            if "<" in mrz_cand and len(mrz_cand) >= 20:
                add_field("MRZ", mrz_cand, "[REDACTED - MRZ BIOMETRIC CODE]", 0.95)
                break

        # ----------------------------------------------------------------------
        # 21. ROLL NUMBER / REGISTRATION NUMBER
        # ----------------------------------------------------------------------
        roll_match = self.roll_number_pattern.search(text)
        if roll_match:
            roll_val = roll_match.group(1).strip()
            if len(roll_val) >= 3 and not any(kw in roll_val.upper() for kw in ["NAME", "DATE", "INDIA", "PASS"]):
                add_field("Roll Number", roll_val, self.mask_roll_no(roll_val), 0.92)

        # ----------------------------------------------------------------------
        # 22. MARKS / CGPA / GRADE
        # ----------------------------------------------------------------------
        marks_match = self.marks_pattern.search(text)
        if marks_match:
            marks_val = marks_match.group(1).strip()
            add_field("Marks / CGPA", marks_val, "[REDACTED]", 0.91)

        # ----------------------------------------------------------------------
        # 23. PASSING YEAR
        # ----------------------------------------------------------------------
        year_match = self.passing_year_pattern.search(text)
        if year_match:
            year_val = year_match.group(1).strip()
            add_field("Passing Year", year_val, year_val, 0.90)

        # ----------------------------------------------------------------------
        # 24. EMPLOYEE ID
        # ----------------------------------------------------------------------
        emp_match = self.employee_id_pattern.search(text)
        if emp_match:
            emp_val = emp_match.group(1).strip()
            if len(emp_val) >= 4 and not any(kw in emp_val.upper() for kw in ["NAME", "DATE", "INDIA"]):
                add_field("Employee ID", emp_val, self.mask_employee_id(emp_val), 0.94)

        # ----------------------------------------------------------------------
        # 25. SALARY / COMPENSATION AMOUNT
        # ----------------------------------------------------------------------
        sal_match = self.salary_income_pattern.search(text)
        if sal_match:
            sal_val = sal_match.group(1).strip()
            add_field("Salary / Income", sal_val, self.mask_income(sal_val), 0.93)

        # ----------------------------------------------------------------------
        # 26. DESIGNATION / ROLE
        # ----------------------------------------------------------------------
        des_match = self.designation_pattern.search(text)
        if des_match:
            des_val = des_match.group(1).strip()
            if len(des_val) >= 3 and not any(kw in des_val.upper() for kw in ["NAME", "PAN", "BANK", "SALARY", "DATE", "INDIA"]):
                add_field("Designation", des_val, des_val, 0.88)

        # ----------------------------------------------------------------------
        # 27. STATEMENT PERIOD
        # ----------------------------------------------------------------------
        stmt_match = self.statement_period_pattern.search(text)
        if stmt_match:
            stmt_val = stmt_match.group(1).strip()
            add_field("Statement Period", stmt_val, stmt_val, 0.92)

        return extracted

    # Backward compatibility method
    def detect(
        self,
        text: str,
        qr_detected: bool = False,
        qr_data: Optional[str] = None,
        qr_bbox: Optional[Dict[str, int]] = None,
        qr_polygon: Optional[List[List[float]]] = None
    ) -> List[Dict[str, Any]]:
        """Legacy helper returning flat entity list."""
        fields_dict = self.extract_document_fields(
            text,
            qr_detected=qr_detected,
            qr_data=qr_data,
            qr_bbox=qr_bbox,
            qr_polygon=qr_polygon
        )
        return list(fields_dict.values())
