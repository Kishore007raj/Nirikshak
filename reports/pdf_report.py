"""
PDF Report generation.
"""

import os
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from core.models import ScanResult

def generate_pdf_report(scan_result: ScanResult) -> str:
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    file_name = f"report_{scan_result.scan_id}.pdf"
    pdf_path = output_dir / file_name
    
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    
    # Title
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, 750, "NIRIKSHAK Security Report")
    
    # Metadata
    c.setFont("Helvetica", 12)
    c.drawString(50, 720, f"Scan ID:   {scan_result.scan_id}")
    c.drawString(50, 700, f"Provider:  {scan_result.provider.upper()}")
    c.drawString(50, 680, f"Timestamp: {scan_result.timestamp}")
    c.drawString(50, 660, f"Risk Score: {scan_result.risk_score}")
    
    sc = scan_result.severity_count or {}
    c.drawString(50, 640, f"Summary:   CRITICAL: {sc.get('CRITICAL', 0)} | HIGH: {sc.get('HIGH', 0)} | "
                          f"MEDIUM: {sc.get('MEDIUM', 0)} | LOW: {sc.get('LOW', 0)}")
                          
    # Findings Header
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, 600, "Findings Summary")
    
    c.setFont("Helvetica", 10)
    y = 570
    
    for idx, f in enumerate(scan_result.findings):
        # Format: [SEVERITY] Resource ID - title
        line = f"[{f.severity}] {f.resource_id} ({f.resource_type})"
        c.drawString(50, y, line)
        y -= 20
        
        # Details
        c.setFont("Helvetica", 9)
        c.drawString(70, y, f"Description: {f.description[:100]}...")
        y -= 20
        c.drawString(70, y, f"Fix: {f.fix_suggestion[:100]}..." if f.fix_suggestion else "Fix: -")
        
        c.setFont("Helvetica", 10)
        y -= 30
        
        if y < 50:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = 750
            
    c.save()
    
    return f"/report/{scan_result.scan_id}"
