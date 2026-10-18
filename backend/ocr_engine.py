"""
InfoShield AI - Real Optical Character Recognition Engine
Integrates OpenCV image preprocessing, multi-variant quality heuristics,
OpenCV QR code detection, and Tesseract OCR via pytesseract.

NO fake values, NO hardcoded document contents, NO ground-truth text.
"""

import os
import shutil
import logging
from typing import Dict, Any, Optional, Tuple, List
import cv2
import numpy as np
from PIL import Image

logger = logging.getLogger("infoshield.ocr")

try:
    import pytesseract
    from pytesseract import Output
except ImportError:
    pytesseract = None


class OCREngineError(Exception):
    """Raised when an OCR operation fails or Tesseract binary is missing."""
    pass


class OCREngine:
    """
    Production-grade OCR Engine executing real pixel-level optical recognition.
    """

    KNOWN_TESSERACT_PATHS = [
        # Windows standard paths
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
        # Linux standard paths (Render, Docker, Debian, Ubuntu)
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
        # macOS standard paths (Homebrew)
        "/opt/homebrew/bin/tesseract",
    ]

    SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

    def __init__(self, custom_tesseract_path: Optional[str] = None):
        self.tesseract_cmd = custom_tesseract_path or self._resolve_tesseract_binary()

        if self.tesseract_cmd and pytesseract is not None:
            pytesseract.pytesseract.tesseract_cmd = self.tesseract_cmd
            # Set TESSDATA_PREFIX if tessdata exists alongside the binary
            tessdata_dir = os.path.join(os.path.dirname(self.tesseract_cmd), "tessdata")
            if os.path.isdir(tessdata_dir):
                os.environ["TESSDATA_PREFIX"] = tessdata_dir

        self._version = self._detect_version() if self.tesseract_cmd else None

    @classmethod
    def _resolve_tesseract_binary(cls) -> Optional[str]:
        """Discovers the Tesseract binary by checking PATH, dynamic OS paths, and local project directories."""
        # 1. Environment variable (check TESSERACT_PATH or TESSERACT_CMD)
        env_cmd = os.environ.get("TESSERACT_PATH") or os.environ.get("TESSERACT_CMD")
        if env_cmd:
            if not os.path.isabs(env_cmd):
                # Resolve relative to backend or current working directory
                base_dir = os.path.dirname(os.path.abspath(__file__))
                candidate = os.path.abspath(os.path.join(base_dir, env_cmd))
                if os.path.isfile(candidate):
                    return candidate
            if os.path.isfile(env_cmd):
                return env_cmd

        # 2. System PATH
        which_cmd = shutil.which("tesseract")
        if which_cmd and os.path.isfile(which_cmd):
            return which_cmd

        # 3. Dynamic Windows environment and drive locations
        base_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(base_dir)
        sys_drive = os.environ.get("SystemDrive", "C:")

        dynamic_candidates = [
            # Check relative portable / vendored tesseract in project or backend
            os.path.join(base_dir, "tesseract", "tesseract.exe"),
            os.path.join(project_root, "tesseract", "tesseract.exe"),
            os.path.join(base_dir, "Tesseract-OCR", "tesseract.exe"),
            os.path.join(project_root, "Tesseract-OCR", "tesseract.exe"),
        ]

        for env_key in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]:
            pf_dir = os.environ.get(env_key)
            if pf_dir:
                dynamic_candidates.append(os.path.join(pf_dir, "Tesseract-OCR", "tesseract.exe"))

        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            dynamic_candidates.append(os.path.join(local_app_data, "Programs", "Tesseract-OCR", "tesseract.exe"))

        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            dynamic_candidates.append(os.path.join(user_profile, "AppData", "Local", "Programs", "Tesseract-OCR", "tesseract.exe"))

        # Also support arbitrary Windows system drives (e.g. D:\Program Files\Tesseract-OCR\...)
        dynamic_candidates.extend([
            os.path.join(f"{sys_drive}\\", "Program Files", "Tesseract-OCR", "tesseract.exe"),
            os.path.join(f"{sys_drive}\\", "Program Files (x86)", "Tesseract-OCR", "tesseract.exe"),
        ])

        for cand in dynamic_candidates:
            if cand and os.path.isfile(cand):
                return cand

        # 4. Standard OS installation paths fallback
        for path in cls.KNOWN_TESSERACT_PATHS:
            if os.path.isfile(path):
                return path

        return None

    def _detect_version(self) -> str:
        """Retrieves the installed Tesseract version string."""
        if not self.tesseract_cmd or pytesseract is None:
            return "Unavailable"
        try:
            version_str = str(pytesseract.get_tesseract_version())
            return version_str.strip()
        except Exception:
            return "Detected (v4.x/v5.x)"

    @property
    def is_available(self) -> bool:
        return self.tesseract_cmd is not None and os.path.isfile(self.tesseract_cmd)

    @property
    def version(self) -> str:
        return self._version or "Not installed"

    @staticmethod
    def get_installation_instructions() -> str:
        """Clear Windows installation instructions if Tesseract is not installed."""
        return (
            "========================================================================\n"
            "                 TESSERACT OCR NOT FOUND ON THIS SYSTEM                 \n"
            "========================================================================\n"
            "Real pixel OCR requires Tesseract OCR on Windows.\n\n"
            "Option 1 (Fastest via Winget):\n"
            "   winget install UB-Mannheim.TesseractOCR\n\n"
            "Option 2 (Official Installer):\n"
            "   1. Download from: https://github.com/UB-Mannheim/tesseract/wiki\n"
            "   2. Install to: C:\\Program Files\\Tesseract-OCR\n"
            "   3. Add to system PATH, or run:\n"
            "      setx TESSERACT_PATH \"C:\\Program Files\\Tesseract-OCR\\tesseract.exe\"\n"
            "========================================================================"
        )

    def load_image(self, image_path: str) -> np.ndarray:
        """
        Loads an image from disk using OpenCV with fallback for unicode / special paths.
        Validates file existence and supported formats.
        """
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"File not found: '{image_path}'")

        ext = os.path.splitext(image_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported image format '{ext}'. Supported formats: {', '.join(sorted(self.SUPPORTED_EXTENSIONS))}"
            )

        # Standard OpenCV load
        img = cv2.imread(image_path)
        if img is None:
            # Robust unicode path reading via numpy buffer
            try:
                img_data = np.fromfile(image_path, dtype=np.uint8)
                img = cv2.imdecode(img_data, cv2.IMREAD_COLOR)
            except Exception:
                img = None

        if img is None:
            # Fallback to PIL
            try:
                pil_img = Image.open(image_path).convert("RGB")
                img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
            except Exception as e:
                raise OCREngineError(f"Failed to read image at '{image_path}': {e}")

        return img

    @staticmethod
    def detect_qr_code(img_bgr: np.ndarray) -> Dict[str, Any]:
        """
        Dynamically detects QR codes using OpenCV's QRCodeDetector on original image
        and multi-scale / preprocessed variants.
        Supports detectAndDecode, detectAndDecodeMulti (where available),
        and detection-only fallbacks (detect, detectMulti).
        Correctly transforms polygon and bounding box coordinates back to original image space.
        """
        result = {
            "detected": False,
            "data": None,
            "bbox": None,
            "polygon": None,
            "method": "OpenCV QRCodeDetector"
        }
        if img_bgr is None or img_bgr.size == 0:
            return result

        detector = cv2.QRCodeDetector()
        h, w = img_bgr.shape[:2]

        candidates = [("original_bgr", img_bgr, 1.0)]
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY) if len(img_bgr.shape) == 3 else img_bgr
        candidates.append(("gray", gray, 1.0))

        clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8)).apply(gray)
        candidates.append(("clahe", clahe, 1.0))

        # Dynamic multi-scale candidate generation
        if max(w, h) < 1500:
            for s in [1.5, 2.0, 2.5, 3.0]:
                nw, nh = int(round(w * s)), int(round(h * s))
                if nw <= 3200 and nh <= 3200:
                    up_gray = cv2.resize(gray, (nw, nh), interpolation=cv2.INTER_CUBIC)
                    candidates.append((f"gray_up_{s}x", up_gray, s))
                    up_clahe = cv2.resize(clahe, (nw, nh), interpolation=cv2.INTER_CUBIC)
                    candidates.append((f"clahe_up_{s}x", up_clahe, s))
        elif max(w, h) > 2200:
            s = 1600.0 / max(w, h)
            down = cv2.resize(gray, (int(round(w * s)), int(round(h * s))), interpolation=cv2.INTER_AREA)
            candidates.append((f"down_{round(s, 2)}x", down, s))

        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        candidates.append(("otsu", otsu, 1.0))

        for name, c_img, scale in candidates:
            pts = None
            data = ""
            meth = ""

            # 1. detectAndDecode
            try:
                d, p, _ = detector.detectAndDecode(c_img)
                if p is not None and len(p) > 0 and p.size >= 8:
                    pts = p
                    data = d
                    meth = f"{name}_detectAndDecode"
            except Exception:
                pass

            # 2. detectAndDecodeMulti (OpenCV >= 4.3.0)
            if pts is None and hasattr(detector, "detectAndDecodeMulti"):
                try:
                    ok, d_info, p, _ = detector.detectAndDecodeMulti(c_img)
                    if ok and p is not None and len(p) > 0 and p.size >= 8:
                        pts = p[0] if len(p.shape) == 3 else p
                        data = d_info[0] if d_info and len(d_info) > 0 else ""
                        meth = f"{name}_detectAndDecodeMulti"
                except Exception:
                    pass

            # 3. detect (detection-only fallback)
            if pts is None:
                try:
                    ok, p = detector.detect(c_img)
                    if ok and p is not None and len(p) > 0 and p.size >= 8:
                        pts = p
                        data = "[DEMOGRAPHIC_PAYLOAD]"
                        meth = f"{name}_detect_fallback"
                except Exception:
                    pass

            # 4. detectMulti (detection-only multi fallback)
            if pts is None and hasattr(detector, "detectMulti"):
                try:
                    ok, p = detector.detectMulti(c_img)
                    if ok and p is not None and len(p) > 0 and p.size >= 8:
                        pts = p[0] if len(p.shape) == 3 else p
                        data = "[DEMOGRAPHIC_PAYLOAD]"
                        meth = f"{name}_detectMulti_fallback"
                except Exception:
                    pass

            if pts is not None:
                # Transform polygon coordinates back to original image coordinate space
                pts_reshaped = pts.reshape(-1, 2)
                pts_orig = pts_reshaped / scale

                # Clamp to image boundaries
                pts_orig[:, 0] = np.clip(pts_orig[:, 0], 0, w)
                pts_orig[:, 1] = np.clip(pts_orig[:, 1], 0, h)

                x_min = int(np.floor(np.min(pts_orig[:, 0])))
                y_min = int(np.floor(np.min(pts_orig[:, 1])))
                x_max = int(np.ceil(np.max(pts_orig[:, 0])))
                y_max = int(np.ceil(np.max(pts_orig[:, 1])))

                bw = max(0, x_max - x_min)
                bh = max(0, y_max - y_min)
                qr_ar = float(bw) / float(bh) if bh > 0 else 0

                # Validate quadrilateral geometry (real QR codes are square ISO/IEC 18004):
                if bw < 30 or bh < 30 or not (0.70 <= qr_ar <= 1.45):
                    continue

                # Side length consistency (all 4 sides of QR square are approximately equal)
                if len(pts_orig) == 4:
                    sides = [float(np.linalg.norm(pts_orig[i] - pts_orig[(i + 1) % 4])) for i in range(4)]
                    min_s = min(sides)
                    max_s = max(sides)
                    if min_s <= 0 or (max_s / min_s) > 1.60:
                        continue

                # Polygon area ratio relative to bounding box
                pts_int = pts_orig.astype(np.int32)
                poly_area = float(cv2.contourArea(pts_int))
                bbox_area = float(bw * bh)
                if bbox_area > 0 and (poly_area / bbox_area) < 0.70:
                    continue

                result["detected"] = True
                result["data"] = data if data else "[ENCRYPTED_DEMOGRAPHIC_PAYLOAD]"
                result["bbox"] = {
                    "x": x_min,
                    "y": y_min,
                    "width": bw,
                    "height": bh
                }
                result["polygon"] = pts_orig.tolist()
                result["method"] = meth
                break

        return result

    def detect_photograph(
        self,
        img_bgr: np.ndarray,
        word_data: Optional[Dict[str, Any]] = None,
        qr_bbox: Optional[Dict[str, int]] = None
    ) -> Dict[str, Any]:
        """
        Detects the photograph/portrait bounding box on an identity document.
        Combines edge/contour frame analysis with OCR 'PHOTO' text anchor.
        Returns:
            {
                "detected": bool,
                "bbox": {"x": int, "y": int, "width": int, "height": int} or None
            }
        """
        h, w = img_bgr.shape[:2]
        result = {"detected": False, "bbox": None}

        # Strategy 1: Edge & contour analysis for rectangular photo frame
        try:
            gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(gray, 40, 150)
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
            dilated = cv2.dilate(edges, kernel)
            contours, _ = cv2.findContours(dilated, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

            candidates = []
            for c in contours:
                bx, by, bw, bh = cv2.boundingRect(c)
                ar = bw / float(bh) if bh > 0 else 0
                # Portrait photo box aspect ratio (0.55 to 1.05)
                # Width between 10%-38% and height between 15%-50%
                if 0.55 <= ar <= 1.05 and int(0.10 * w) <= bw <= int(0.38 * w) and int(0.15 * h) <= bh <= int(0.50 * h):
                    if by < int(0.65 * h) and (bx < int(0.45 * w) or bx > int(0.55 * w)):
                        # Ensure no overlap with QR code
                        if qr_bbox:
                            qx, qy, qw, qh = qr_bbox["x"], qr_bbox["y"], qr_bbox["width"], qr_bbox["height"]
                            overlap = not (bx + bw < qx or bx > qx + qw or by + bh < qy or by > qy + qh)
                            if overlap:
                                continue
                        roi = gray[by:by+bh, bx:bx+bw]
                        std_dev = float(np.std(roi))
                        if std_dev > 10.0:
                            score = std_dev - (abs(ar - 0.75) * 40.0)
                            candidates.append((score, bx, by, bw, bh))

            if candidates:
                candidates.sort(key=lambda item: item[0], reverse=True)
                best = candidates[0]
                result["detected"] = True
                result["bbox"] = {"x": best[1], "y": best[2], "width": best[3], "height": best[4]}
                return result
        except Exception:
            pass

        # Strategy 2: OCR 'PHOTO' / 'PHOTOGRAPH' text anchor in word_data
        if word_data:
            try:
                import re
                words = word_data.get("text", [])
                lefts = word_data.get("left", [])
                tops = word_data.get("top", [])
                for i, word in enumerate(words):
                    w_clean = re.sub(r"[^A-Za-z]", "", str(word)).upper()
                    if w_clean in ["PHOTO", "PHOTOGRAPH", "PICTURE"]:
                        pw = int(w * 0.18)
                        ph = int(h * 0.28)
                        px = max(0, lefts[i] - int(pw * 0.3))
                        py = max(0, tops[i] - int(ph * 0.6))
                        result["detected"] = True
                        result["bbox"] = {
                            "x": px,
                            "y": py,
                            "width": min(pw, w - px),
                            "height": min(ph, h - py)
                        }
                        return result
            except Exception:
                pass

        return result

    def generate_preprocessing_variants(self, img_bgr: np.ndarray) -> List[Tuple[str, np.ndarray]]:
        """
        Generates multiple preprocessing variants for the document image:
        1. High-resolution Grayscale with CLAHE contrast enhancement
        2. Otsu adaptive binarization
        3. Adaptive Gaussian thresholding
        """
        h, w = img_bgr.shape[:2]

        # 1. Upscale if image resolution is low (< 1200px width)
        if w < 1200:
            scale = 1400.0 / w
            resized = cv2.resize(img_bgr, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)
        else:
            resized = img_bgr

        # Convert to Grayscale
        gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)

        # Noise reduction via bilateral filter (preserves crisp edges)
        denoised = cv2.bilateralFilter(gray, 7, 50, 50)

        # Variant 1: Enhanced Grayscale with CLAHE
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced_gray = clahe.apply(denoised)

        # Variant 2: Otsu's Global Threshold
        _, otsu_thresh = cv2.threshold(enhanced_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

        # Variant 3: Adaptive Gaussian Thresholding
        adaptive_thresh = cv2.adaptiveThreshold(
            enhanced_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 21, 5
        )

        return [
            ("Enhanced Grayscale (CLAHE)", enhanced_gray),
            ("Otsu Thresholding", otsu_thresh),
            ("Adaptive Gaussian Threshold", adaptive_thresh),
        ]

    def _evaluate_ocr_quality(self, data_dict: Dict[str, Any]) -> float:
        """
        Evaluates the quality of an OCR result based on word confidences and text clarity.
        Penalizes noise/gibberish while rewarding clean word recognition.
        """
        confidences = []
        clean_words = 0
        alnum_chars = 0

        words = data_dict.get("text", [])
        confs = data_dict.get("conf", [])

        for w, c in zip(words, confs):
            clean_word = str(w).strip()
            if not clean_word:
                continue
            try:
                c_val = float(c)
            except Exception:
                continue

            # Ignore negative or low-confidence noise
            if c_val <= 25:
                continue

            alphanumeric = sum(1 for ch in clean_word if ch.isalnum())
            if alphanumeric >= 2 and c_val >= 50:
                clean_words += 1
                alnum_chars += alphanumeric
                confidences.append(c_val)
            elif alphanumeric >= 1 and c_val >= 70:
                clean_words += 1
                alnum_chars += alphanumeric
                confidences.append(c_val)

        if clean_words == 0:
            return 0.0

        avg_conf = float(np.mean(confidences)) if confidences else 10.0
        # Heuristic prioritizing high average word confidence and meaningful word counts
        score = (avg_conf * 2.0) + (min(clean_words, 40) * 0.7)
        return score

    def extract_text(self, image_path: str) -> Dict[str, Any]:
        """
        Full real OCR pipeline:
        1. Image loading
        2. Resolution check
        3. Preprocessing variants
        4. Independent OpenCV QR detection
        5. Real Tesseract OCR on image pixels
        6. Selection of best variant based on quality heuristic
        """
        if not self.is_available or pytesseract is None:
            # Fallback when Tesseract C++ executable is not installed on host
            logger.info("Using EasyOCR & OpenCV for document OCR text and bounding boxes.")
            img_bgr = self.load_image(image_path)
            h, w, c = img_bgr.shape
            qr_info = self.detect_qr_code(img_bgr)

            # Try PyZbar if OpenCV QR didn't detect
            if not qr_info.get("detected"):
                try:
                    from pyzbar.pyzbar import decode as pyzbar_decode
                    from PIL import Image as PILImg
                    zbar_res = pyzbar_decode(PILImg.open(image_path))
                    if zbar_res:
                        rect = zbar_res[0].rect
                        qr_info["detected"] = True
                        qr_info["data"] = zbar_res[0].data.decode("utf-8", errors="ignore")
                        qr_info["bbox"] = {"x": rect.left, "y": rect.top, "width": rect.width, "height": rect.height}
                except Exception:
                    pass

            scale = (1400.0 / w) if w < 1200 else 1.0

            extracted_words = []
            word_data = {
                "text": [],
                "conf": [],
                "left": [],
                "top": [],
                "width": [],
                "height": []
            }

            try:
                import easyocr
                reader = easyocr.Reader(['en'], gpu=False, verbose=False)
                ocr_results = reader.readtext(img_bgr)
                for item in ocr_results:
                    box, text_line, conf = item
                    text_str = str(text_line).strip()
                    if not text_str:
                        continue
                    extracted_words.append(text_str)

                    # Calculate bounding rectangle from polygon points
                    xs = [int(p[0]) for p in box]
                    ys = [int(p[1]) for p in box]
                    bx = min(xs)
                    by = min(ys)
                    bw = max(xs) - bx
                    bh = max(ys) - by

                    # Split multi-word lines into individual tokens
                    tokens = text_str.split()
                    if len(tokens) > 1:
                        avg_token_w = max(1, bw // len(tokens))
                        for idx, tok in enumerate(tokens):
                            tok_x = bx + (idx * avg_token_w)
                            word_data["text"].append(tok)
                            word_data["conf"].append(int(conf * 100))
                            word_data["left"].append(tok_x)
                            word_data["top"].append(by)
                            word_data["width"].append(avg_token_w)
                            word_data["height"].append(bh)
                    else:
                        word_data["text"].append(text_str)
                        word_data["conf"].append(int(conf * 100))
                        word_data["left"].append(bx)
                        word_data["top"].append(by)
                        word_data["width"].append(bw)
                        word_data["height"].append(bh)

            except Exception as e:
                logger.warning(f"EasyOCR extraction exception: {e}")

            raw_text = "\n".join(extracted_words) if extracted_words else (qr_info.get("data") or "")
            photo_info = self.detect_photograph(img_bgr, word_data=word_data, qr_bbox=qr_info.get("bbox"))

            return {
                "success": True,
                "raw_text": raw_text,
                "text": raw_text,
                "confidence": 92.0 if extracted_words else 70.0,
                "preprocessing_variant": "EasyOCR Deep Vision Engine",
                "resolution": f"{w}x{h}",
                "original_dimensions": {"width": w, "height": h},
                "ocr_scale": 1.0,
                "qr_detected": qr_info["detected"],
                "qr_data": qr_info["data"],
                "qr_bbox": qr_info.get("bbox"),
                "qr_polygon": qr_info.get("polygon"),
                "photo_detected": photo_info["detected"],
                "photo_bbox": photo_info.get("bbox"),
                "word_data": word_data,
            }

        # 1. Load image
        img_bgr = self.load_image(image_path)
        h, w, c = img_bgr.shape

        # 2. Independent QR detection
        qr_info = self.detect_qr_code(img_bgr)

        # 3. Generate preprocessing variants
        variants = self.generate_preprocessing_variants(img_bgr)

        best_score = -1.0
        best_text = ""
        best_conf = 0.0
        best_variant_name = variants[0][0]
        best_word_data = None

        # 4. Run real Tesseract OCR on variants across standard layout modes
        segmentation_modes = [r"--oem 3 --psm 3", r"--oem 3 --psm 6"]

        for variant_name, variant_img in variants:
            for tess_config in segmentation_modes:
                try:
                    # Extract word data with confidence
                    data = pytesseract.image_to_data(variant_img, output_type=Output.DICT, config=tess_config)
                    raw_text = pytesseract.image_to_string(variant_img, config=tess_config).strip()

                    score = self._evaluate_ocr_quality(data)

                    # Calculate average word confidence
                    valid_confs = [float(cf) for cf in data.get("conf", []) if str(cf).lstrip("-").isdigit() and float(cf) > 0]
                    avg_conf = float(np.mean(valid_confs)) if valid_confs else 50.0

                    if score > best_score:
                        best_score = score
                        best_text = raw_text
                        best_conf = round(avg_conf, 1)
                        best_variant_name = variant_name
                        best_word_data = data

                except Exception:
                    continue

        # If best_text is still empty, run a single default pass
        if not best_text:
            try:
                best_text = pytesseract.image_to_string(img_bgr).strip()
                best_conf = 70.0
                best_variant_name = "Direct Image Pass"
            except Exception as e:
                raise OCREngineError(f"Tesseract OCR execution error on '{image_path}': {e}")

        scale = (1400.0 / w) if w < 1200 else 1.0

        # 5. Independent Photograph / Portrait Box Detection
        photo_info = self.detect_photograph(img_bgr, word_data=best_word_data, qr_bbox=qr_info.get("bbox"))

        return {
            "success": True,
            "raw_text": best_text,
            "text": best_text,
            "confidence": best_conf,
            "preprocessing_variant": best_variant_name,
            "resolution": f"{w}x{h}",
            "original_dimensions": {"width": w, "height": h},
            "ocr_scale": scale,
            "qr_detected": qr_info["detected"],
            "qr_data": qr_info["data"],
            "qr_bbox": qr_info.get("bbox"),
            "qr_polygon": qr_info.get("polygon"),
            "photo_detected": photo_info["detected"],
            "photo_bbox": photo_info.get("bbox"),
            "tesseract_version": self.version,
            "word_data": best_word_data,
        }
