"""
InfoShield AI - Synthetic Sample Document Generator
Creates realistic synthetic document images with purely fictional information for prototype testing.
Contains ZERO real PII.
"""

import os
import sys
from PIL import Image, ImageDraw, ImageFont

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def draw_qr_mock(draw: ImageDraw.ImageDraw, top_left: tuple, size: int = 100):
    """Draws a recognizable geometric QR code block for optical detection."""
    x, y = top_left
    # Background
    draw.rectangle([x, y, x + size, y + size], fill="#FFFFFF", outline="#000000", width=2)
    # 3 Position Detection Patterns (Finder Patterns)
    box_size = 24
    inner_size = 12
    # Top-left
    draw.rectangle([x + 6, y + 6, x + 6 + box_size, y + 6 + box_size], fill="#000000")
    draw.rectangle([x + 10, y + 10, x + 2 + box_size, y + 2 + box_size], fill="#FFFFFF")
    draw.rectangle([x + 12, y + 12, x + inner_size + 12, y + inner_size + 12], fill="#000000")
    # Top-right
    tr_x = x + size - box_size - 6
    draw.rectangle([tr_x, y + 6, tr_x + box_size, y + 6 + box_size], fill="#000000")
    draw.rectangle([tr_x + 4, y + 10, tr_x + box_size - 4, y + 2 + box_size], fill="#FFFFFF")
    draw.rectangle([tr_x + 6, y + 12, tr_x + inner_size + 6, y + inner_size + 12], fill="#000000")
    # Bottom-left
    bl_y = y + size - box_size - 6
    draw.rectangle([x + 6, bl_y, x + 6 + box_size, bl_y + box_size], fill="#000000")
    draw.rectangle([x + 10, bl_y + 4, x + 2 + box_size, bl_y + box_size - 4], fill="#FFFFFF")
    draw.rectangle([x + 12, bl_y + 6, x + inner_size + 12, bl_y + inner_size + 6], fill="#000000")
    # Timing patterns and mock data bits
    for i in range(x + 36, x + size - 36, 8):
        draw.rectangle([i, y + 16, i + 4, y + 20], fill="#000000")
        draw.rectangle([i, y + 40, i + 4, y + 44], fill="#000000")
        draw.rectangle([i, y + 64, i + 4, y + 68], fill="#000000")
        draw.rectangle([x + 16, y + i - x, x + 20, y + i - x + 4], fill="#000000")
        draw.rectangle([x + 48, y + i - x, x + 52, y + i - x + 4], fill="#000000")


def create_sample_aadhaar(output_dir: str):
    """Creates synthetic Aadhaar-style document with fictional data."""
    width, height = 750, 480
    img = Image.new("RGB", (width, height), color="#FDFBF7")
    draw = ImageDraw.Draw(img)

    # Decorative header
    draw.rectangle([0, 0, width, 55], fill="#1E3A8A")
    draw.text((25, 14), "GOVERNMENT OF INDIA", fill="#FFFFFF")
    draw.text((25, 30), "UNIQUE IDENTIFICATION AUTHORITY OF INDIA", fill="#E2E8F0")

    # Document content
    draw.text((40, 80), "To,", fill="#334155")
    draw.text((40, 105), "Name: Aarav Sharma", fill="#0F172A")
    draw.text((40, 135), "DOB: 14/05/1998", fill="#0F172A")
    draw.text((40, 165), "Gender: Male", fill="#0F172A")
    draw.text((40, 195), "Address: Flat 402, Green Meadows, Andheri East,", fill="#0F172A")
    draw.text((40, 220), "Mumbai, Maharashtra - 400069", fill="#0F172A")

    # Aadhaar 12-digit number (large & bold)
    draw.rectangle([35, 290, 715, 360], fill="#EFF6FF", outline="#93C5FD", width=2)
    draw.text((200, 310), "9823  4567  9012", fill="#1E3A8A")

    draw.text((160, 380), "Mera Aadhaar, Meri Pehchan (Synthetic Test Specimen)", fill="#64748B")

    # QR Code block
    draw_qr_mock(draw, (580, 85), size=120)

    # Save PNG image
    img_path = os.path.join(output_dir, "sample_aadhaar.png")
    img.save(img_path, "PNG")

    # Save sidecar ground-truth text
    txt_path = os.path.join(output_dir, "sample_aadhaar.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(
            "GOVERNMENT OF INDIA\n"
            "UNIQUE IDENTIFICATION AUTHORITY OF INDIA\n"
            "To,\n"
            "Name: Aarav Sharma\n"
            "DOB: 14/05/1998\n"
            "Gender: Male\n"
            "Address: Flat 402, Green Meadows, Andheri East, Mumbai, Maharashtra - 400069\n"
            "9823 4567 9012\n"
            "Mera Aadhaar, Meri Pehchan (Synthetic Test Specimen)\n"
        )


def create_sample_ordinary(output_dir: str):
    """Creates ordinary text document with zero high-risk PII."""
    width, height = 750, 480
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    # Header
    draw.rectangle([0, 0, width, 45], fill="#0F172A")
    draw.text((25, 14), "DEPARTMENT OF COMPUTER SCIENCE & ENGINEERING", fill="#FFFFFF")

    # Text content
    draw.text((40, 75), "COURSE SYLLABUS: CS402 - DISTRIBUTED SYSTEMS", fill="#0F172A")
    draw.line([(40, 95), (710, 95)], fill="#CBD5E1", width=1)

    draw.text((40, 120), "Term: Fall Semester 2026", fill="#334155")
    draw.text((40, 150), "Overview: Fundamentals of distributed algorithms, consensus mechanisms,", fill="#334155")
    draw.text((40, 175), "Byzantine fault tolerance, and secure multiparty verification.", fill="#334155")

    draw.text((40, 220), "Grading Structure:", fill="#0F172A")
    draw.text((60, 245), "- Midterm Examination: 30%", fill="#475569")
    draw.text((60, 270), "- Practical Lab Assignments: 30%", fill="#475569")
    draw.text((60, 295), "- Final Capstone Research Paper: 40%", fill="#475569")

    draw.text((40, 350), "Office Hours: Tuesday & Thursday, 14:00 - 16:00 (Building 4, Room 302)", fill="#64748B")

    # Save PNG image
    img_path = os.path.join(output_dir, "sample_ordinary.png")
    img.save(img_path, "PNG")

    # Save sidecar ground-truth text
    txt_path = os.path.join(output_dir, "sample_ordinary.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(
            "DEPARTMENT OF COMPUTER SCIENCE & ENGINEERING\n"
            "COURSE SYLLABUS: CS402 - DISTRIBUTED SYSTEMS\n"
            "Term: Fall Semester 2026\n"
            "Overview: Fundamentals of distributed algorithms, consensus mechanisms, Byzantine fault tolerance.\n"
            "Grading Structure:\n"
            "- Midterm Examination: 30%\n"
            "- Practical Lab Assignments: 30%\n"
            "- Final Capstone Research Paper: 40%\n"
            "Office Hours: Tuesday & Thursday, 14:00 - 16:00 (Building 4, Room 302)\n"
        )


def create_sample_multi_pii(output_dir: str):
    """Creates a multi-PII document with Name, Email, Phone, PAN, Account, DOB, and Address."""
    width, height = 750, 480
    img = Image.new("RGB", (width, height), color="#F8FAFC")
    draw = ImageDraw.Draw(img)

    # Header
    draw.rectangle([0, 0, width, 50], fill="#047857")
    draw.text((25, 15), "SECURE FINANCIAL ONBOARDING & KYC VERIFICATION FORM", fill="#FFFFFF")

    # Fields
    draw.text((40, 75), "Applicant Name: Rohan K. Verma", fill="#0F172A")
    draw.text((40, 105), "Date of Birth: 22/11/1995", fill="#0F172A")
    draw.text((40, 135), "Email: rohan.verma@fintechmail.com", fill="#0F172A")
    draw.text((40, 165), "Phone: +91 98765 43210", fill="#0F172A")
    draw.text((40, 195), "PAN Number: ABCDE1234F", fill="#0F172A")
    draw.text((40, 225), "Bank Account Number: 50100492817291", fill="#0F172A")
    draw.text((40, 255), "IFSC Code: HDFC0001234", fill="#0F172A")
    draw.text((40, 285), "Address: Sector 18, Block B, Noida, Uttar Pradesh 201301", fill="#0F172A")

    draw.rectangle([35, 330, 715, 390], fill="#ECFDF5", outline="#A7F3D0", width=1)
    draw.text((50, 345), "NOTICE: Contains confidential banking identifiers and personal records.", fill="#065F46")
    draw.text((50, 365), "Strict Purpose Minimization required before external dissemination.", fill="#047857")

    # Save PNG image
    img_path = os.path.join(output_dir, "sample_multi_pii.png")
    img.save(img_path, "PNG")

    # Save sidecar ground-truth text
    txt_path = os.path.join(output_dir, "sample_multi_pii.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(
            "SECURE FINANCIAL ONBOARDING & KYC VERIFICATION FORM\n"
            "Applicant Name: Rohan K. Verma\n"
            "Date of Birth: 22/11/1995\n"
            "Email: rohan.verma@fintechmail.com\n"
            "Phone: +91 98765 43210\n"
            "PAN Number: ABCDE1234F\n"
            "Bank Account Number: 50100492817291\n"
            "IFSC Code: HDFC0001234\n"
            "Address: Sector 18, Block B, Noida, Uttar Pradesh 201301\n"
            "NOTICE: Contains confidential banking identifiers and personal records.\n"
        )


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.abspath(os.path.join(script_dir, "..", "backend"))
    target_dir = os.path.join(backend_dir, "samples")
    os.makedirs(target_dir, exist_ok=True)
    print(f"Generating synthetic test documents in: {target_dir}")

    create_sample_aadhaar(target_dir)
    print("✓ Created sample_aadhaar.png & sample_aadhaar.txt")

    create_sample_ordinary(target_dir)
    print("✓ Created sample_ordinary.png & sample_ordinary.txt")

    create_sample_multi_pii(target_dir)
    print("✓ Created sample_multi_pii.png & sample_multi_pii.txt")

    print("\nSynthetic sample generation completed successfully!")


if __name__ == "__main__":
    main()
