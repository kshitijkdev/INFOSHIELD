"""
InfoShield AI - Test Image Generator
Creates realistic synthetic test document images in test_images/
Contains purely fictional test data with ZERO real personal information.
Uses clean typography compatible with all standard Windows system fonts.
"""

import os
import sys

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import qrcode
from PIL import Image, ImageDraw, ImageFont


def get_font(size: int, bold: bool = False):
    """Attempts to load a standard system font, falling back to default."""
    font_names = [
        "segoeuib.ttf" if bold else "segoeui.ttf",
        "arialbd.ttf" if bold else "arial.ttf",
        "calibrib.ttf" if bold else "calibri.ttf"
    ]
    for name in font_names:
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default()
    except Exception:
        return None


def generate_test_aadhaar(output_path: str):
    """Generates synthetic Aadhaar card with text and genuine QR code."""
    width, height = 1100, 700
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(28, bold=True)
    f_sub = get_font(20, bold=True)
    f_body = get_font(22, bold=False)
    f_bold = get_font(22, bold=True)
    f_aadhaar = get_font(42, bold=True)
    f_footer = get_font(16, bold=False)

    # Top Header Band
    draw.rectangle([0, 0, width, 85], fill="#1E3A8A")
    draw.rectangle([0, 85, width, 92], fill="#DC2626")

    draw.text((40, 16), "GOVERNMENT OF INDIA", fill="#FFFFFF", font=f_title)
    draw.text((40, 50), "Unique Identification Authority of India", fill="#E2E8F0", font=f_sub)

    # Photo Box
    draw.rectangle([50, 130, 230, 360], fill="#F1F5F9", outline="#94A3B8", width=2)
    draw.ellipse([100, 170, 180, 250], fill="#94A3B8")
    draw.chord([80, 240, 200, 340], start=0, end=180, fill="#94A3B8")
    draw.text((105, 330), "PHOTO", fill="#64748B", font=f_footer)

    # Demographic Details
    start_x = 270
    draw.text((start_x, 130), "To,", fill="#475569", font=f_body)
    draw.text((start_x, 165), "Name: Aarav Sharma", fill="#0F172A", font=f_bold)
    draw.text((start_x, 200), "DOB: 14/05/1998", fill="#0F172A", font=f_body)
    draw.text((start_x, 235), "Gender: Male", fill="#0F172A", font=f_body)
    draw.text((start_x, 270), "Mobile: 9876543210", fill="#0F172A", font=f_body)
    draw.text((start_x, 305), "Address: Flat 402, Green Meadows, Andheri East,", fill="#0F172A", font=f_body)
    draw.text((start_x, 335), "Mumbai, Maharashtra - 400069", fill="#0F172A", font=f_body)

    # Genuine Scannable QR Code
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data("<?xml version='1.0'?><UidData uid='982345679012' name='Aarav Sharma' dob='14/05/1998' gender='M' yob='1998' co='S/O Rajesh Sharma' house='Flat 402' loc='Green Meadows' vtc='Mumbai' po='Andheri' dist='Mumbai' subdist='Andheri' state='Maharashtra' pc='400069'/>")
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_img = qr_img.resize((190, 190))
    img.paste(qr_img, (860, 140))

    # Aadhaar Number Banner
    draw.rectangle([50, 400, width - 50, 490], fill="#F8FAFC", outline="#2563EB", width=2)
    draw.text((310, 420), "9823  4567  9012", fill="#1E3A8A", font=f_aadhaar)

    # VID
    draw.text((370, 505), "VID: 9123 4567 8901 2345", fill="#475569", font=f_sub)

    draw.line([(50, 550), (width - 50, 550)], fill="#CBD5E1", width=1)

    # Bottom slogans & Notice
    draw.text((310, 570), "Mera Aadhaar, Meri Pehchan (My Aadhaar, My Identity)", fill="#0F172A", font=f_sub)
    draw.text((250, 620), "[SYNTHETIC TEST SPECIMEN - STRICTLY FICTIONAL DATA FOR AI SCANNER TESTING]", fill="#EF4444", font=f_footer)

    img.save(output_path, "PNG")
    print(f"✓ Generated: {output_path}")


def generate_test_pan(output_path: str):
    """Generates synthetic PAN card."""
    width, height = 1100, 700
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(26, bold=True)
    f_sub = get_font(20, bold=True)
    f_body = get_font(22, bold=False)
    f_bold = get_font(22, bold=True)
    f_pan = get_font(38, bold=True)
    f_footer = get_font(16, bold=False)

    # Header
    draw.rectangle([0, 0, width, 85], fill="#0284C7")
    draw.text((40, 15), "INCOME TAX DEPARTMENT", fill="#FFFFFF", font=f_title)
    draw.text((40, 48), "GOVT. OF INDIA", fill="#E0F2FE", font=f_sub)

    # Photo Box
    draw.rectangle([50, 140, 220, 350], fill="#F1F5F9", outline="#94A3B8", width=2)
    draw.text((95, 230), "PHOTO", fill="#64748B", font=f_body)

    # Details
    draw.text((260, 140), "Name: ROHAN VERMA", fill="#0F172A", font=f_bold)
    draw.text((260, 200), "Father's Name: K S VERMA", fill="#0F172A", font=f_body)
    draw.text((260, 260), "Date of Birth: 22/11/1995", fill="#0F172A", font=f_bold)

    # PAN Box
    draw.rectangle([50, 420, width - 50, 520], fill="#F0F9FF", outline="#0284C7", width=2)
    draw.text((100, 445), "Permanent Account Number: ", fill="#0369A1", font=f_body)
    draw.text((450, 440), "ABCDE1234F", fill="#0369A1", font=f_pan)

    # Synthetic disclaimer
    draw.text((240, 620), "[SYNTHETIC PAN CARD - ZERO REAL PERSONAL IDENTIFIABLE DATA]", fill="#EF4444", font=f_footer)

    img.save(output_path, "PNG")
    print(f"✓ Generated: {output_path}")


def generate_clean_syllabus(output_path: str):
    """Generates clean syllabus document with zero PII."""
    width, height = 1100, 700
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(26, bold=True)
    f_sub = get_font(20, bold=True)
    f_body = get_font(20, bold=False)

    draw.rectangle([0, 0, width, 65], fill="#0F172A")
    draw.text((40, 18), "DEPARTMENT OF COMPUTER SCIENCE & ENGINEERING", fill="#FFFFFF", font=f_title)

    draw.text((50, 100), "COURSE SYLLABUS: CS402 - DISTRIBUTED SYSTEMS & ZERO-TRUST SECURITY", fill="#0F172A", font=f_sub)
    draw.line([(50, 135), (width - 50, 135)], fill="#E2E8F0", width=2)

    draw.text((50, 160), "Semester: Fall 2026 | Credits: 4.0 | Level: Advanced Undergraduate", fill="#475569", font=f_body)
    draw.text((50, 205), "Course Overview:", fill="#0F172A", font=f_sub)
    draw.text((50, 240), "This course introduces distributed algorithms, consensus mechanisms (Paxos, Raft),", fill="#334155", font=f_body)
    draw.text((50, 275), "cryptographic proofs, zero-knowledge verifications, and privacy-preserving data architectures.", fill="#334155", font=f_body)

    draw.text((50, 340), "Grading Scheme:", fill="#0F172A", font=f_sub)
    draw.text((70, 380), "• Midterm Examination: 30%", fill="#334155", font=f_body)
    draw.text((70, 420), "• Practical Lab Assignments & Security Audits: 30%", fill="#334155", font=f_body)
    draw.text((70, 460), "• Final Capstone Implementation: 40%", fill="#334155", font=f_body)

    draw.text((50, 540), "Office Hours: Tuesday & Thursday, 14:00 - 16:00 (Building 4, Room 302)", fill="#64748B", font=f_body)
    draw.text((50, 620), "General Public Document - Free Distribution Authorized.", fill="#10B981", font=f_body)

    img.save(output_path, "PNG")
    print(f"✓ Generated: {output_path}")


def generate_test_driving_licence(output_path: str):
    """Generates synthetic Driving Licence with photograph, licence number, validity, etc."""
    width, height = 1100, 700
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(26, bold=True)
    f_sub = get_font(18, bold=True)
    f_body = get_font(21, bold=False)
    f_bold = get_font(21, bold=True)
    f_dl = get_font(30, bold=True)
    f_footer = get_font(15, bold=False)

    # Top Header Band
    draw.rectangle([0, 0, width, 85], fill="#047857")
    draw.text((40, 16), "UNION OF INDIA - DRIVING LICENCE", fill="#FFFFFF", font=f_title)
    draw.text((40, 50), "GOVERNMENT OF MAHARASHTRA - MOTOR VEHICLES DEPARTMENT", fill="#D1FAE5", font=f_sub)

    # Photo Box (Width: 180, Height: 220, AR: 180/220 = 0.818)
    draw.rectangle([60, 130, 240, 350], fill="#F1F5F9", outline="#047857", width=2)
    draw.ellipse([110, 160, 190, 240], fill="#64748B")
    draw.chord([85, 230, 215, 330], start=0, end=180, fill="#64748B")
    draw.text((115, 325), "PHOTO", fill="#475569", font=f_footer)

    # Licence Details
    start_x = 280
    draw.text((start_x, 130), "Licence No: MH02 2018 0092341", fill="#047857", font=f_dl)
    draw.text((start_x, 180), "Name: VIKRAM RAJESH SHINDE", fill="#0F172A", font=f_bold)
    draw.text((start_x, 215), "DOB: 15/08/1992", fill="#0F172A", font=f_body)
    draw.text((start_x, 250), "Blood Group: B+ve", fill="#0F172A", font=f_bold)
    draw.text((start_x, 285), "Authorised to Drive: LMV, MCWG", fill="#0F172A", font=f_body)
    draw.text((start_x, 320), "Valid Till: 14/08/2032", fill="#0F172A", font=f_bold)

    # Address Box
    draw.rectangle([50, 400, width - 50, 530], fill="#F8FAFC", outline="#CBD5E1", width=1)
    draw.text((70, 415), "Address: Flat 12, Sunrise Apartments, Linking Road, Bandra West,", fill="#0F172A", font=f_body)
    draw.text((70, 450), "Mumbai, Maharashtra - 400050", fill="#0F172A", font=f_body)
    draw.text((70, 490), "Issuing Authority: RTO MUMBAI WEST (MH-02)", fill="#475569", font=f_sub)

    # Bottom Notice
    draw.text((220, 620), "[SYNTHETIC DRIVING LICENCE - ZERO REAL PERSONAL DATA FOR TESTING]", fill="#EF4444", font=f_footer)

    img.save(output_path, "PNG")
    print(f"✓ Generated: {output_path}")


def generate_test_passport(output_path: str):
    """Generates synthetic Passport specimen with MRZ, photo, and passport number."""
    width, height = 1100, 700
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(26, bold=True)
    f_sub = get_font(18, bold=True)
    f_body = get_font(21, bold=False)
    f_bold = get_font(21, bold=True)
    f_pass = get_font(30, bold=True)
    f_mrz = get_font(22, bold=True)
    f_footer = get_font(15, bold=False)

    # Top Header Band
    draw.rectangle([0, 0, width, 85], fill="#1E293B")
    draw.text((40, 16), "REPUBLIC OF INDIA - PASSPORT", fill="#FFFFFF", font=f_title)
    draw.text((40, 50), "PASSPORT / PASSEPORT - OFFICIAL BIOGRAPHICAL DATA PAGE", fill="#CBD5E1", font=f_sub)

    # Photo Box
    draw.rectangle([60, 120, 240, 340], fill="#F1F5F9", outline="#1E293B", width=2)
    draw.ellipse([110, 150, 190, 230], fill="#64748B")
    draw.chord([85, 220, 215, 320], start=0, end=180, fill="#64748B")
    draw.text((115, 315), "PHOTO", fill="#475569", font=f_footer)

    # Passport Details
    start_x = 280
    draw.text((start_x, 120), "Passport No: Z8923412", fill="#1E293B", font=f_pass)
    draw.text((start_x, 165), "Surname: SHARMA", fill="#0F172A", font=f_bold)
    draw.text((start_x, 195), "Given Name: PRIYA ANAND", fill="#0F172A", font=f_bold)
    draw.text((start_x, 225), "Nationality: INDIAN", fill="#0F172A", font=f_body)
    draw.text((start_x, 255), "Date of Birth: 19/04/1997", fill="#0F172A", font=f_body)
    draw.text((start_x, 285), "Place of Birth: MUMBAI", fill="#0F172A", font=f_body)
    draw.text((start_x, 315), "Valid Till: 18/04/2034", fill="#0F172A", font=f_bold)

    # MRZ Machine Readable Zone Box
    draw.rectangle([50, 430, width - 50, 560], fill="#F8FAFC", outline="#94A3B8", width=1)
    draw.text((70, 450), "P<INDSHARMA<<PRIYA<ANAND<<<<<<<<<<<<<<<<<<<<<<<<<", fill="#0F172A", font=f_mrz)
    draw.text((70, 495), "Z8923412<4IND9704198F3404184<<<<<<<<<<<<<<<<<<<04", fill="#0F172A", font=f_mrz)

    # Bottom Notice
    draw.text((220, 620), "[SYNTHETIC PASSPORT SPECIMEN - ZERO REAL PERSONAL DATA FOR TESTING]", fill="#EF4444", font=f_footer)

    img.save(output_path, "PNG")
    print(f"✓ Generated: {output_path}")


def generate_test_bank_statement(output_path: str):
    """Generates synthetic Bank Statement specimen."""
    width, height = 1100, 700
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(26, bold=True)
    f_sub = get_font(18, bold=True)
    f_body = get_font(20, bold=False)
    f_bold = get_font(20, bold=True)
    f_amt = get_font(26, bold=True)
    f_footer = get_font(15, bold=False)

    # Header
    draw.rectangle([0, 0, width, 85], fill="#1E40AF")
    draw.text((40, 16), "STATE BANK OF INDIA", fill="#FFFFFF", font=f_title)
    draw.text((40, 50), "ACCOUNT STATEMENT & FINANCIAL SUMMARY", fill="#DBEAFE", font=f_sub)

    # Account Info
    draw.text((50, 110), "Account Holder: AARAV RAJESH SHARMA", fill="#0F172A", font=f_bold)
    draw.text((50, 145), "Account Number: 309182746501", fill="#1E40AF", font=f_bold)
    draw.text((50, 180), "IFSC Code: SBIN0001234", fill="#0F172A", font=f_body)
    draw.text((50, 215), "Statement Period: 01/01/2026 to 31/03/2026", fill="#0F172A", font=f_bold)
    draw.text((50, 250), "Address: Flat 402, Green Meadows, Andheri East, Mumbai - 400069", fill="#0F172A", font=f_body)

    # Summary Box
    draw.rectangle([50, 310, width - 50, 440], fill="#EFF6FF", outline="#1E40AF", width=2)
    draw.text((70, 330), "Closing Balance: ₹1,84,520.00", fill="#1E40AF", font=f_amt)
    draw.text((70, 375), "Total Credit Deposits: ₹3,50,000.00", fill="#047857", font=f_bold)
    draw.text((550, 375), "Total Debit Withdrawals: ₹1,65,480.00", fill="#B91C1C", font=f_bold)

    # Transaction Sample Table
    draw.rectangle([50, 460, width - 50, 560], fill="#F8FAFC", outline="#CBD5E1", width=1)
    draw.text((70, 475), "Recent Salary Credit: 31/03/2026  NEFT SALARY APEX TECH  +₹98,500.00", fill="#0F172A", font=f_body)
    draw.text((70, 510), "Semester Tuition Fee: 15/03/2026  UPI COLLEGE ADMISSION  -₹45,000.00", fill="#0F172A", font=f_body)

    draw.text((220, 620), "[SYNTHETIC BANK STATEMENT - ZERO REAL PERSONAL DATA FOR TESTING]", fill="#EF4444", font=f_footer)

    img.save(output_path, "PNG")
    print(f"✓ Generated: {output_path}")


def generate_test_marksheet(output_path: str):
    """Generates synthetic Educational Marksheet specimen."""
    width, height = 1100, 700
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(26, bold=True)
    f_sub = get_font(18, bold=True)
    f_body = get_font(20, bold=False)
    f_bold = get_font(20, bold=True)
    f_footer = get_font(15, bold=False)

    # Header
    draw.rectangle([0, 0, width, 85], fill="#854D0E")
    draw.text((40, 16), "CENTRAL BOARD OF SECONDARY EDUCATION", fill="#FFFFFF", font=f_title)
    draw.text((40, 50), "SENIOR SCHOOL CERTIFICATE EXAMINATION - 2024 (MARKSHEET)", fill="#FEF08A", font=f_sub)

    # Student Info
    draw.text((50, 110), "Candidate Name: ROHAN K VERMA", fill="#0F172A", font=f_bold)
    draw.text((50, 145), "Roll Number: 2617894", fill="#854D0E", font=f_bold)
    draw.text((50, 180), "Registration No: CBSE/2024/DEL/8912", fill="#0F172A", font=f_body)
    draw.text((50, 215), "Year of Passing: 2024", fill="#0F172A", font=f_bold)
    draw.text((50, 250), "School: Delhi Public School, R.K. Puram, New Delhi", fill="#0F172A", font=f_body)

    # Marks Box
    draw.rectangle([50, 300, width - 50, 480], fill="#FEFCE8", outline="#854D0E", width=1)
    draw.text((70, 315), "Subject Code & Name                Theory   Practical   Total Marks", fill="#854D0E", font=f_bold)
    draw.text((70, 350), "301  English Core                     68        20          88", fill="#0F172A", font=f_body)
    draw.text((70, 380), "041  Mathematics                      74        18          92", fill="#0F172A", font=f_body)
    draw.text((70, 410), "042  Physics                          62        28          90", fill="#0F172A", font=f_body)
    draw.text((70, 440), "083  Computer Science                 67        28          95", fill="#0F172A", font=f_body)

    # Summary
    draw.text((70, 510), "Total Marks: 451/500", fill="#0F172A", font=f_bold)
    draw.text((380, 510), "CGPA: 9.02", fill="#047857", font=f_bold)
    draw.text((650, 510), "Result: PASS", fill="#047857", font=f_bold)

    draw.text((220, 620), "[SYNTHETIC EDUCATIONAL MARKSHEET - ZERO REAL PERSONAL DATA FOR TESTING]", fill="#EF4444", font=f_footer)

    img.save(output_path, "PNG")
    print(f"✓ Generated: {output_path}")


def generate_test_salary_slip(output_path: str):
    """Generates synthetic Salary Slip / Employment Document specimen."""
    width, height = 1100, 700
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(26, bold=True)
    f_sub = get_font(18, bold=True)
    f_body = get_font(20, bold=False)
    f_bold = get_font(20, bold=True)
    f_amt = get_font(24, bold=True)
    f_footer = get_font(15, bold=False)

    # Header
    draw.rectangle([0, 0, width, 85], fill="#374151")
    draw.text((40, 16), "APEX TECHNOLOGIES PVT LTD", fill="#FFFFFF", font=f_title)
    draw.text((40, 50), "EMPLOYMENT & SALARY SLIP - AUGUST 2026", fill="#E5E7EB", font=f_sub)

    # Employee Details
    draw.text((50, 110), "Employee Name: VIKRAM RAJESH SHINDE", fill="#0F172A", font=f_bold)
    draw.text((50, 145), "Employee ID: EMP-40912", fill="#374151", font=f_bold)
    draw.text((50, 180), "Designation: Senior Software Engineer", fill="#0F172A", font=f_body)
    draw.text((50, 215), "PAN Number: ABCDE1234F", fill="#0F172A", font=f_bold)
    draw.text((50, 250), "Bank Account Number: 50100492817291", fill="#0F172A", font=f_body)

    # Salary Summary Box
    draw.rectangle([50, 300, width - 50, 480], fill="#F3F4F6", outline="#374151", width=1)
    draw.text((70, 320), "Basic Pay: ₹65,000.00", fill="#0F172A", font=f_body)
    draw.text((500, 320), "Provident Fund (PF): ₹7,800.00", fill="#0F172A", font=f_body)
    draw.text((70, 360), "HRA: ₹30,000.00", fill="#0F172A", font=f_body)
    draw.text((500, 360), "Tax Deducted (TDS): ₹18,700.00", fill="#0F172A", font=f_body)
    draw.text((70, 400), "Gross Salary: ₹1,25,000.00", fill="#047857", font=f_amt)
    draw.text((500, 400), "Total Deductions: ₹26,500.00", fill="#B91C1C", font=f_amt)
    draw.text((70, 440), "Net Pay: ₹98,500.00", fill="#1E40AF", font=f_amt)

    draw.text((220, 620), "[SYNTHETIC SALARY SLIP - ZERO REAL PERSONAL DATA FOR TESTING]", fill="#EF4444", font=f_footer)

    img.save(output_path, "PNG")
    print(f"✓ Generated: {output_path}")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.abspath(os.path.join(script_dir, "..", "backend"))
    test_dir = os.path.join(backend_dir, "test_images")
    os.makedirs(test_dir, exist_ok=True)

    test_doc = os.path.join(test_dir, "test_document.png")
    pan_doc = os.path.join(test_dir, "pan_sample.png")
    clean_doc = os.path.join(test_dir, "clean_syllabus.png")
    dl_doc = os.path.join(test_dir, "driving_licence_sample.png")
    passport_doc = os.path.join(test_dir, "passport_sample.png")
    bank_doc = os.path.join(test_dir, "bank_statement_sample.png")
    marksheet_doc = os.path.join(test_dir, "marksheet_sample.png")
    salary_doc = os.path.join(test_dir, "salary_slip_sample.png")

    generate_test_aadhaar(test_doc)
    generate_test_pan(pan_doc)
    generate_clean_syllabus(clean_doc)
    generate_test_driving_licence(dl_doc)
    generate_test_passport(passport_doc)
    generate_test_bank_statement(bank_doc)
    generate_test_marksheet(marksheet_doc)
    generate_test_salary_slip(salary_doc)

    readme_path = os.path.join(test_dir, "README.txt")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(
            "InfoShield AI - Test Images Directory\n"
            "======================================\n\n"
            "This folder contains test specimens for real OCR and PII scanning.\n\n"
            "Pre-generated synthetic test images:\n"
            "  1. test_document.png          - Synthetic Aadhaar specimen with genuine scannable QR code\n"
            "  2. pan_sample.png              - Synthetic PAN Card specimen\n"
            "  3. clean_syllabus.png          - Academic document with zero PII (unknown/clean classification)\n"
            "  4. driving_licence_sample.png  - Synthetic Driving Licence specimen with photograph\n"
            "  5. passport_sample.png         - Synthetic Passport specimen with MRZ and photo\n"
            "  6. bank_statement_sample.png   - Synthetic Bank Statement specimen with balances and transactions\n"
            "  7. marksheet_sample.png        - Synthetic CBSE Educational Marksheet with marks and CGPA\n"
            "  8. salary_slip_sample.png      - Synthetic Employment Payslip with earnings and employee ID\n\n"
            "All specimens contain purely fictional, non-sensitive testing data.\n"
        )
    print(f"✓ Created: {readme_path}")


if __name__ == "__main__":
    main()

