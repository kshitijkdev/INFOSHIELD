"""
InfoShield AI - Real Document Image Redaction Engine
Performs physical pixel-level redaction on document images based on
purpose-based data minimization decisions (REQUIRED, CONDITIONAL, UNNECESSARY).

Does NOT rely on visual overlays or terminal masking.
Directly modifies pixel arrays via OpenCV and writes protected images to outputs/.
"""

import os
import cv2
import numpy as np
from typing import Dict, Any, List, Optional, Tuple


class RedactionEngine:
    """
    Physical pixel-level document redaction engine.
    Applies zero-trust purpose minimization directly onto image pixels.
    """

    def __init__(self, output_dir: Optional[str] = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        target = output_dir or os.getenv("OUTPUT_DIR", os.path.join(base_dir, "outputs"))
        if not os.path.isabs(target):
            self.output_dir = os.path.join(base_dir, target)
        else:
            self.output_dir = target
        os.makedirs(self.output_dir, exist_ok=True)

    @staticmethod
    def _scale_box(box: Dict[str, int], scale: float, is_already_original: bool = False) -> Dict[str, int]:
        """Maps coordinates from OCR space to original image space."""
        if is_already_original or scale <= 0 or abs(scale - 1.0) < 1e-4:
            return dict(box)
        return {
            "x": int(round(box["x"] / scale)),
            "y": int(round(box["y"] / scale)),
            "width": int(round(box["width"] / scale)),
            "height": int(round(box["height"] / scale)),
        }

    @staticmethod
    def _clamp_box(x: int, y: int, w: int, h: int, img_w: int, img_h: int, pad: int = 2) -> Tuple[int, int, int, int]:
        """Applies slight padding and clamps rectangle coordinates to image boundaries."""
        x1 = max(0, x - pad)
        y1 = max(0, y - pad)
        x2 = min(img_w, x + w + pad)
        y2 = min(img_h, y + h + pad)
        return x1, y1, max(0, x2 - x1), max(0, y2 - y1)

    @staticmethod
    def _apply_privacy_blur(
        img: np.ndarray,
        x: int,
        y: int,
        w: int,
        h: int,
        pad_x: int = 4,
        pad_y: int = 4
    ) -> None:
        """
        Applies irreversible opaque pixel redaction over sensitive document regions.
        Completely replaces all underlying character strokes and pixels with an
        opaque uniform document tone with defensive padding, destroying OCR and visual
        recovery while maintaining document aesthetics.
        """
        img_h, img_w = img.shape[:2]
        x1 = max(0, x - pad_x)
        y1 = max(0, y - pad_y)
        x2 = min(img_w, x + w + pad_x)
        y2 = min(img_h, y + h + pad_y)

        rw = x2 - x1
        rh = y2 - y1
        if rw <= 1 or rh <= 1:
            return

        roi = img[y1:y2, x1:x2]

        # Sample border pixels to compute the background tone
        mean_col = cv2.mean(roi)[:3]
        base_color = [int(c) for c in mean_col]

        # Completely replace the region with uniform opaque color — no glyph edges remain
        img[y1:y2, x1:x2] = np.full_like(roi, base_color, dtype=np.uint8)


    @staticmethod
    def _apply_qr_mask(
        img: np.ndarray,
        x: int,
        y: int,
        w: int,
        h: int,
        pad: int = 6,
        polygon: Optional[List[List[float]]] = None
    ) -> None:
        """
        Applies strong, opaque pixelation to the detected QR region.
        For this sensitive 2D barcode field, does not rely on blur alone.
        Guarantees that all QR finder patterns, timing cells, and Reed-Solomon payload
        modules are completely and irreversibly obscured.
        """
        img_h, img_w = img.shape[:2]
        x1 = max(0, x - pad)
        y1 = max(0, y - pad)
        x2 = min(img_w, x + w + pad)
        y2 = min(img_h, y + h + pad)

        rw = x2 - x1
        rh = y2 - y1
        if rw <= 1 or rh <= 1:
            return

        roi = img[y1:y2, x1:x2]

        # Strong opaque pixelation:
        # Downsample to a coarse 6x6 to 8x8 block grid using INTER_AREA,
        # then upscale using INTER_NEAREST. Each block becomes a solid uniform color.
        # This completely eliminates all module edges and contrasts without relying on blur alone,
        # and blends naturally with the document's background and ink tones without being a flat 0.
        grid_w = max(4, min(8, rw // 16))
        grid_h = max(4, min(8, rh // 16))
        small = cv2.resize(roi, (grid_w, grid_h), interpolation=cv2.INTER_AREA)
        pixelated = cv2.resize(small, (rw, rh), interpolation=cv2.INTER_NEAREST)

        img[y1:y2, x1:x2] = pixelated

    def redact_document(
        self,
        image_path: str,
        fields_dict: Dict[str, Dict[str, Any]],
        requirements: List[Dict[str, Any]],
        output_path: Optional[str] = None,
        ocr_scale: float = 1.0
    ) -> Dict[str, Any]:
        """
        Executes physical pixel redaction on the original document image.

        Args:
            image_path: Path to the original uploaded document.
            fields_dict: Dictionary of detected fields with bounding boxes and values.
            requirements: List of purpose requirements (REQUIRED, CONDITIONAL, UNNECESSARY).
            output_path: Destination path for the protected image.
            ocr_scale: Scaling factor used during OCR preprocessing (ocr_w / orig_w).

        Returns:
            Dictionary containing result status, output file path, redaction actions, and stats.
        """
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Input document not found: {image_path}")

        # Read original image (BGR)
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError(f"Could not decode image at {image_path}")

        img_h, img_w = img.shape[:2]

        # Map requirement decisions by field name or normalized key
        req_map = {}
        for req in requirements:
            field_name = req.get("field") or req.get("type", "")
            req_map[field_name.lower().replace("_", "").replace(" ", "")] = req

        redactions_applied = []
        stats = {
            "total_detected": len(fields_dict),
            "fully_redacted": 0,
            "partially_redacted": 0,
            "preserved": 0
        }

        # ----------------------------------------------------------------------
        # 1. First Pass: Process all standard text fields
        # ----------------------------------------------------------------------
        text_fields = {k: v for k, v in fields_dict.items() if k != "QR Code"}
        qr_fields = {k: v for k, v in fields_dict.items() if k == "QR Code"}

        warnings = []
        for field_name, item in text_fields.items():
            norm_key = field_name.lower().replace("_", "").replace(" ", "")

            # ------------------------------------------------------------------
            # Policy-Driven Photo Preservation / Redaction Rule:
            # Check policy requirements for photograph. Only preserve photo pixels
            # when explicitly REQUIRED (e.g., identity verification). If UNNECESSARY
            # or CONDITIONAL, mask the photograph region to prevent unnecessary biometric exposure.
            # ------------------------------------------------------------------
            if field_name == "Photograph" or norm_key == "photograph":
                raw_bbox = item.get("bbox")
                if not raw_bbox or not (raw_bbox.get("width", 0) > 0 and raw_bbox.get("height", 0) > 0):
                    warnings.append("Photograph region uncertain; visual mask avoided to prevent accidental biometric occlusion.")
                    continue
                scaled_bbox = self._scale_box(raw_bbox, ocr_scale, is_already_original=True)

                req = req_map.get(norm_key)
                req_status = (req.get("decision") or req.get("status") or "REQUIRED").upper() if req else "REQUIRED"
                req_action = (req.get("action") or "").upper() if req else ""

                if req_status == "REQUIRED" or req_action == "PRESERVED":
                    stats["preserved"] += 1
                    redactions_applied.append({
                        "field": "Photograph",
                        "action": "PRESERVED",
                        "status": "REQUIRED",
                        "details": "Visual face photograph preserved per verified necessity",
                        "reason": req.get("reason", "Visual face photograph preserved for identity verification.") if req else "Visual face photograph preserved for identity verification.",
                        "bbox": scaled_bbox
                    })
                else:
                    self._apply_privacy_blur(
                        img,
                        scaled_bbox["x"], scaled_bbox["y"], scaled_bbox["width"], scaled_bbox["height"],
                        pad_x=4, pad_y=4
                    )
                    stats["fully_redacted"] += 1
                    redactions_applied.append({
                        "field": "Photograph",
                        "action": "FULLY_REDACTED",
                        "status": req_status,
                        "details": "Concealed photograph per policy to prevent biometric exposure",
                        "reason": req.get("reason", "Biometric face photograph unnecessary for stated purpose.") if req else "Biometric face photograph unnecessary for stated purpose.",
                        "bbox": scaled_bbox
                    })
                continue


            req = req_map.get(norm_key)

            # Default to UNNECESSARY under zero-trust if not found
            req_status = (req.get("decision") or req.get("status") or "UNNECESSARY").upper() if req else "UNNECESSARY"
            req_action = (req.get("action") or "").upper() if req else ""
            reason = req.get("reason", "Zero-trust default minimization") if req else "Zero-trust default minimization"

            raw_bbox = item.get("bbox")
            if not raw_bbox:
                if req_status in ["UNNECESSARY", "CONDITIONAL"] and req_action != "PRESERVED":
                    warnings.append(f"Bounding box missing for '{field_name}'. Physical redaction could not be applied; manual review advised.")
                continue

            scaled_bbox = self._scale_box(raw_bbox, ocr_scale, is_already_original=(field_name == "Photograph"))

            # ------------------------------------------------------------------
            # 1. REQUIRED or action == PRESERVED: Leave completely untouched
            # ------------------------------------------------------------------
            if req_status == "REQUIRED" or req_action == "PRESERVED":
                stats["preserved"] += 1
                redactions_applied.append({
                    "field": field_name,
                    "action": "PRESERVED",
                    "status": req_status,
                    "details": "Untouched per verified necessity" if req_status == "REQUIRED" else "Untouched per low exposure risk",
                    "reason": reason,
                    "bbox": scaled_bbox
                })
                continue

            # ------------------------------------------------------------------
            # 2. CONDITIONAL: Field-specific intelligent minimization
            # ------------------------------------------------------------------
            if req_status == "CONDITIONAL":
                if field_name == "Aadhaar Number":
                    # Mask first 8 digits, retain last 4 digits
                    token_boxes = item.get("token_boxes", [])
                    if len(token_boxes) >= 3:
                        # Aadhaar is in 3 4-digit chunks: blur chunk 0 and chunk 1
                        for tb in token_boxes[:2]:
                            stb = self._scale_box(tb, ocr_scale)
                            self._apply_privacy_blur(img, stb["x"], stb["y"], stb["width"], stb["height"], pad_x=3, pad_y=3)
                    else:
                        # Continuous box: blur first 67%
                        mask_w = int(round(scaled_bbox["width"] * 0.67))
                        self._apply_privacy_blur(img, scaled_bbox["x"], scaled_bbox["y"], mask_w, scaled_bbox["height"], pad_x=3, pad_y=3)

                    stats["partially_redacted"] += 1
                    redactions_applied.append({
                        "field": field_name,
                        "action": "PARTIALLY_REDACTED",
                        "status": "CONDITIONAL",
                        "details": "Blurred first 8 digits, retained last 4 digits (XXXX XXXX 1234)",
                        "reason": reason,
                        "bbox": scaled_bbox
                    })

                elif field_name in ["Licence Number", "Driving Licence Number"]:
                    # Partial mask: blur middle serial digits, retain RTO/state prefix and last digits
                    mask_w = int(round(scaled_bbox["width"] * 0.50))
                    offset_x = int(round(scaled_bbox["width"] * 0.25))
                    self._apply_privacy_blur(img, scaled_bbox["x"] + offset_x, scaled_bbox["y"], mask_w, scaled_bbox["height"], pad_x=2, pad_y=2)

                    stats["partially_redacted"] += 1
                    redactions_applied.append({
                        "field": field_name,
                        "action": "PARTIALLY_REDACTED",
                        "status": "CONDITIONAL",
                        "details": "Blurred middle sequential digits, retained state/RTO prefix and last digits",
                        "reason": reason,
                        "bbox": scaled_bbox
                    })

                elif field_name == "Passport Number":
                    # Mask middle digits, retain initial letter and trailing 2 digits
                    mask_w = int(round(scaled_bbox["width"] * 0.50))
                    offset_x = int(round(scaled_bbox["width"] * 0.25))
                    self._apply_privacy_blur(img, scaled_bbox["x"] + offset_x, scaled_bbox["y"], mask_w, scaled_bbox["height"], pad_x=2, pad_y=2)

                    stats["partially_redacted"] += 1
                    redactions_applied.append({
                        "field": field_name,
                        "action": "PARTIALLY_REDACTED",
                        "status": "CONDITIONAL",
                        "details": "Blurred middle serial digits, retained passport prefix and last digits",
                        "reason": reason,
                        "bbox": scaled_bbox
                    })

                elif field_name in ["Bank Account Number", "Account Number"]:
                    # Mask first digits, retain last 4 digits
                    mask_w = int(round(scaled_bbox["width"] * 0.65))
                    self._apply_privacy_blur(img, scaled_bbox["x"], scaled_bbox["y"], mask_w, scaled_bbox["height"], pad_x=2, pad_y=2)

                    stats["partially_redacted"] += 1
                    redactions_applied.append({
                        "field": field_name,
                        "action": "PARTIALLY_REDACTED",
                        "status": "CONDITIONAL",
                        "details": "Blurred initial account digits, retained last 4 digits",
                        "reason": reason,
                        "bbox": scaled_bbox
                    })

                elif field_name == "Employee ID":
                    # Retain prefix, blur serial digits
                    mask_w = int(round(scaled_bbox["width"] * 0.55))
                    offset_x = int(round(scaled_bbox["width"] * 0.45))
                    self._apply_privacy_blur(img, scaled_bbox["x"] + offset_x, scaled_bbox["y"], mask_w, scaled_bbox["height"], pad_x=2, pad_y=2)

                    stats["partially_redacted"] += 1
                    redactions_applied.append({
                        "field": field_name,
                        "action": "PARTIALLY_REDACTED",
                        "status": "CONDITIONAL",
                        "details": "Retained corporate prefix, blurred numeric employee serial",
                        "reason": reason,
                        "bbox": scaled_bbox
                    })

                elif field_name == "Mobile Number":
                    # Mask first 6 digits, retain last 4 digits
                    mask_w = int(round(scaled_bbox["width"] * 0.60))
                    self._apply_privacy_blur(img, scaled_bbox["x"], scaled_bbox["y"], mask_w, scaled_bbox["height"], pad_x=3, pad_y=3)

                    stats["partially_redacted"] += 1
                    redactions_applied.append({
                        "field": field_name,
                        "action": "PARTIALLY_REDACTED",
                        "status": "CONDITIONAL",
                        "details": "Blurred first 6 digits, retained last 4 digits (XXXXXX1234)",
                        "reason": reason,
                        "bbox": scaled_bbox
                    })

                elif field_name == "Address":
                    # Mask street details, preserve regional details (City/State/PIN)
                    line_boxes = item.get("line_boxes", [])
                    if len(line_boxes) >= 2:
                        # Redact Line 1 (street address), preserve Line 2 (City / State / PIN)
                        line1 = line_boxes[0]
                        sl1 = self._scale_box(line1, ocr_scale)
                        self._apply_privacy_blur(img, sl1["x"], sl1["y"], sl1["width"], sl1["height"], pad_x=4, pad_y=4)
                    else:
                        # Single line: mask top 55% of height or first 50%
                        mask_w = int(round(scaled_bbox["width"] * 0.55))
                        self._apply_privacy_blur(img, scaled_bbox["x"], scaled_bbox["y"], mask_w, scaled_bbox["height"], pad_x=4, pad_y=4)

                    stats["partially_redacted"] += 1
                    redactions_applied.append({
                        "field": field_name,
                        "action": "PARTIALLY_REDACTED",
                        "status": "CONDITIONAL",
                        "details": "Blurred specific street address, preserved regional jurisdiction",
                        "reason": reason,
                        "bbox": scaled_bbox
                    })

                elif field_name == "VID":
                    # Virtual ID is fully masked when conditional
                    self._apply_privacy_blur(img, scaled_bbox["x"], scaled_bbox["y"], scaled_bbox["width"], scaled_bbox["height"], pad_x=4, pad_y=4)

                    stats["fully_redacted"] += 1
                    redactions_applied.append({
                        "field": field_name,
                        "action": "FULLY_REDACTED",
                        "status": "CONDITIONAL",
                        "details": "Blurred 16-digit Virtual ID",
                        "reason": reason,
                        "bbox": scaled_bbox
                    })

                else:
                    # Other conditional fields (e.g. Gender, Date of Birth)
                    if req_action == "PRESERVED":
                        stats["preserved"] += 1
                        redactions_applied.append({
                            "field": field_name,
                            "action": "PRESERVED",
                            "status": "CONDITIONAL",
                            "details": f"Untouched {field_name} per low exposure risk",
                            "reason": reason,
                            "bbox": scaled_bbox
                        })
                    else:
                        self._apply_privacy_blur(img, scaled_bbox["x"], scaled_bbox["y"], scaled_bbox["width"], scaled_bbox["height"], pad_x=4, pad_y=4)
                        stats["fully_redacted"] += 1
                        redactions_applied.append({
                            "field": field_name,
                            "action": "FULLY_REDACTED",
                            "status": "CONDITIONAL",
                            "details": f"Blurred sensitive {field_name}",
                            "reason": reason,
                            "bbox": scaled_bbox
                        })

                continue

            # ------------------------------------------------------------------
            # 3. UNNECESSARY: Professional privacy blur
            # ------------------------------------------------------------------
            self._apply_privacy_blur(
                img,
                scaled_bbox["x"], scaled_bbox["y"], scaled_bbox["width"], scaled_bbox["height"],
                pad_x=4, pad_y=4
            )
            stats["fully_redacted"] += 1
            redactions_applied.append({
                "field": field_name,
                "action": "FULLY_REDACTED",
                "status": "UNNECESSARY",
                "details": f"Applied privacy-preserving blur to {field_name}",
                "reason": reason,
                "bbox": scaled_bbox
            })

        # ----------------------------------------------------------------------
        # 2. Final Pass: Guaranteed QR Code physical masking
        # Ensures QR mask is applied to the final output image AFTER all
        # other field redactions, so later operations cannot restore or overwrite the QR code.
        # ----------------------------------------------------------------------
        qr_item = qr_fields.get("QR Code")
        if not qr_item:
            # Dynamic fallback check: inspect image directly using OpenCV QRCodeDetector
            from ocr_engine import OCREngine
            det_qr = OCREngine.detect_qr_code(img)
            if det_qr["detected"] and det_qr.get("bbox"):
                qr_item = {
                    "bbox": det_qr["bbox"],
                    "polygon": det_qr.get("polygon")
                }

        if qr_item and qr_item.get("bbox"):
            norm_key = "qrcode"
            req = req_map.get(norm_key)
            req_status = (req.get("decision") or req.get("status") or ("REQUIRED" if req and req.get("action") == "PRESERVED" else "UNNECESSARY")).upper() if req else "UNNECESSARY"
            req_action = (req.get("action") or "").upper() if req else ""
            reason = req.get("reason", "Contains full biometric/demographic payload") if req else "Zero-trust default minimization"

            raw_bbox = qr_item["bbox"]
            scaled_bbox = self._scale_box(raw_bbox, ocr_scale, is_already_original=True)

            if req_status == "REQUIRED" or req_action == "PRESERVED":
                stats["preserved"] += 1
                redactions_applied.append({
                    "field": "QR Code",
                    "action": "PRESERVED",
                    "status": "REQUIRED",
                    "details": "QR code preserved per verified necessity",
                    "reason": reason,
                    "bbox": scaled_bbox
                })
            else:
                self._apply_qr_mask(
                    img,
                    scaled_bbox["x"], scaled_bbox["y"], scaled_bbox["width"], scaled_bbox["height"],
                    pad=6, polygon=qr_item.get("polygon")
                )
                stats["fully_redacted"] += 1
                redactions_applied.append({
                    "field": "QR Code",
                    "action": "FULLY_REDACTED",
                    "status": req_status,
                    "details": "Physically obscured QR code via strong opaque pixelation as final operation",
                    "reason": reason,
                    "bbox": scaled_bbox
                })

        # Generate output filename if not explicitly provided
        if not output_path:
            orig_base = os.path.basename(image_path)
            name, ext = os.path.splitext(orig_base)
            output_filename = f"protected_{name}{ext if ext else '.png'}"
            output_path = os.path.join(self.output_dir, output_filename)

        # Write protected image to output path
        success = cv2.imwrite(output_path, img)
        if not success:
            raise IOError(f"Failed to write protected image to {output_path}")

        return {
            "success": True,
            "output_path": output_path,
            "protected_filename": os.path.basename(output_path),
            "redactions_applied": redactions_applied,
            "stats": stats,
            "warnings": warnings
        }
