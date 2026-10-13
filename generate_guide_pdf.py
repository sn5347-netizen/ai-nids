import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def create_project_guide_pdf(filename="CyberShield_NIDS_Complete_Project_Guide.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0f172a'),
        alignment=0,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0284c7'),
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#334155'),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'BulletText',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'CodeSnippet',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#0f172a'),
        backColor=colors.HexColor('#f1f5f9'),
        borderPadding=6,
        spaceAfter=8
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1e293b'),
        backColor=colors.HexColor('#e0f2fe'),
        borderPadding=8,
        spaceAfter=10
    )

    elements = []

    # Title & Header
    elements.append(Paragraph("🛡️ CyberShield: AI-Powered Network Intrusion Detection System", title_style))
    elements.append(Paragraph("Comprehensive Technical Guide, Architecture Breakdown & Interview Study Notes", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

    # Section 1: How to Re-Open Anytime
    elements.append(Paragraph("1. How to Re-Open and Run the Project Anytime", h1_style))
    elements.append(Paragraph(
        "Whenever you close your computer or VS Code and come back later, you can start everything in seconds using either of these two methods:",
        body_style
    ))
    elements.append(Paragraph("<b>Method A: 1-Click Launch (Easiest)</b>", h2_style))
    elements.append(Paragraph(
        "Navigate to your project folder: <code>C:\\Users\\shiva\\OneDrive\\Desktop\\ai-nids</code> and simply <b>double-click <code>start.bat</code></b>. It opens both the backend and frontend automatically.",
        body_style
    ))
    elements.append(Paragraph("<b>Method B: Running via VS Code Terminal</b>", h2_style))
    elements.append(Paragraph("1. Open VS Code ➔ File ➔ Open Folder ➔ <code>C:\\Users\\shiva\\OneDrive\\Desktop\\ai-nids</code>", bullet_style))
    elements.append(Paragraph("2. Terminal 1 (Backend): <code>cd backend ; ..\\venv\\Scripts\\activate ; uvicorn app.main:app --reload --port 8000</code>", bullet_style))
    elements.append(Paragraph("3. Terminal 2 (Frontend): <code>cd frontend ; npm run dev</code>", bullet_style))
    elements.append(Paragraph("4. Open your browser and navigate to: <b><u>http://localhost:5173</u></b>", bullet_style))

    # Section 2: Executive Summary
    elements.append(Paragraph("2. Executive Summary & Problem Solved", h1_style))
    elements.append(Paragraph(
        "Modern corporate networks process millions of packets per second. Traditional firewalls and intrusion systems rely purely on static signatures (known virus patterns). Consequently, they are blind to novel zero-day attacks, slow stealth port scans, and volumetric floods.",
        body_style
    ))
    elements.append(Paragraph(
        "<b>CyberShield AI-NIDS</b> solves this by coupling <b>Unsupervised Machine Learning (Isolation Forest)</b> with a <b>Stateful Heuristic Engine</b> and a <b>GenAI Incident Response Copilot</b>. It delivers real-time packet inspection, composite risk scoring (0-100), automated MITRE ATT&CK mapping, and 1-click firewall containment scripts through an interactive SOC dashboard.",
        body_style
    ))

    # Section 3: Architecture
    elements.append(Paragraph("3. System Architecture & Components", h1_style))
    arch_data = [
        [Paragraph("<b>Component</b>", body_style), Paragraph("<b>Technology</b>", body_style), Paragraph("<b>Responsibility</b>", body_style)],
        [Paragraph("Packet Ingestion", body_style), Paragraph("Scapy / Python", body_style), Paragraph("Raw TCP/IP, UDP, ICMP packet capture and simulation.", body_style)],
        [Paragraph("Feature Extractor", body_style), Paragraph("NumPy / Pandas", body_style), Paragraph("Converts packet streams into 12-dimensional numerical vectors.", body_style)],
        [Paragraph("Anomaly Engine", body_style), Paragraph("Scikit-learn", body_style), Paragraph("Isolation Forest model detecting zero-day and outlier behaviors.", body_style)],
        [Paragraph("Heuristic Engine", body_style), Paragraph("Python Stateful Rules", body_style), Paragraph("Sliding-window algorithms for Port Scanning and DoS floods.", body_style)],
        [Paragraph("Risk Scorer", body_style), Paragraph("Composite Scorer", body_style), Paragraph("Normalizes ML certainty + heuristic hits into a 0-100 Risk Score.", body_style)],
        [Paragraph("AI Copilot", body_style), Paragraph("GenAI / Rule Engine", body_style), Paragraph("Maps attacks to MITRE ATT&CK & outputs firewall containment rules.", body_style)],
        [Paragraph("Backend Server", body_style), Paragraph("FastAPI + Uvicorn", body_style), Paragraph("High-speed async REST endpoints and WebSocket telemetry pipe.", body_style)],
        [Paragraph("Database", body_style), Paragraph("SQLite / PostgreSQL", body_style), Paragraph("SQLAlchemy persistence for historical alerts and threat logs.", body_style)],
        [Paragraph("SOC Dashboard", body_style), Paragraph("React 19 + Tailwind", body_style), Paragraph("Live risk gauges, threat table, Recharts, and AI modal.", body_style)],
    ]
    t = Table(arch_data, colWidths=[1.3*inch, 1.4*inch, 4.3*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 10))

    # Section 4: Machine Learning Deep-Dive
    elements.append(Paragraph("4. Machine Learning Deep-Dive: Isolation Forest", h1_style))
    elements.append(Paragraph(
        "<b>Why Isolation Forest instead of Supervised Learning?</b> In real-world cyber defense, malicious traffic represents less than 0.1% of all traffic, and attackers constantly invent new patterns. Supervised models (like Random Forests or Neural Networks) require labelled attack data and fail on zero-days. Isolation Forest is <i>unsupervised</i>: it models what 'normal' baseline network traffic looks like, without needing predefined attack labels.",
        body_style
    ))
    elements.append(Paragraph(
        "<b>How Isolation Forest Works:</b> The algorithm isolates observations by randomly selecting a feature and then randomly selecting a split value. Because anomalies are few and have distinct attribute values (e.g. huge packet size, strange TCP flags, unusual destination ports), they are isolated closer to the root of the decision trees with fewer splits. Normal data points require deeper splits to be isolated.",
        body_style
    ))
    elements.append(Paragraph("<b>The 12-Dimensional Feature Vector:</b>", h2_style))
    elements.append(Paragraph("• <code>packet_length</code>: Raw byte size (abnormal sizes indicate tunneling or payload injection).", bullet_style))
    elements.append(Paragraph("• <code>proto_tcp, proto_udp, proto_icmp</code>: One-hot encoded protocol indicators.", bullet_style))
    elements.append(Paragraph("• <code>is_well_known_port</code>: 1 if port &lt; 1024 (standard web/mail/DNS), 0 for high ports.", bullet_style))
    elements.append(Paragraph("• <code>dst_port_norm</code>: Normalized destination port (dst_port / 65535).", bullet_style))
    elements.append(Paragraph("• <code>flag_syn, flag_ack, flag_fin, flag_rst</code>: TCP flag indicators.", bullet_style))
    elements.append(Paragraph("• <code>packet_rate</code>: Recent packet burst rate (packets per second in 3s window).", bullet_style))
    elements.append(Paragraph("• <code>port_diversity</code>: Number of distinct destination ports probed by the IP in 8s.", bullet_style))

    # Section 5: Heuristic Detection
    elements.append(Paragraph("5. Heuristic & Signature Detection", h1_style))
    elements.append(Paragraph(
        "While ML detects unknown anomalies, known attack patterns require fast, deterministic rules:",
        body_style
    ))
    elements.append(Paragraph("• <b>Port Scanning:</b> Tracks connection requests across a sliding 8-second window. If a single IP targets 8 or more unique ports or sends multiple SYN packets without ACK handshakes, it triggers a Port Scan alert.", bullet_style))
    elements.append(Paragraph("• <b>Denial-of-Service (DoS) SYN Flood:</b> When packet frequency from an IP crosses 40 packets/second, it flags volumetric resource exhaustion.", bullet_style))
    elements.append(Paragraph("• <b>Stealth Flag Anomalies:</b> Detects <i>TCP NULL Scans</i> (packets with 0 flags) and <i>XMAS Scans</i> (simultaneous FIN, PSH, and URG flags) used by tools like Nmap to evade simple packet filters.", bullet_style))

    # Section 6: Composite Risk Scoring
    elements.append(Paragraph("6. Composite 0-100 Risk Scoring Engine", h1_style))
    elements.append(Paragraph(
        "Instead of simple binary 'safe/unsafe' flags, our engine computes a normalized <b>Composite Risk Score (0 to 100)</b> by fusing Heuristic Confidence Points with the Isolation Forest decision function:",
        body_style
    ))
    elements.append(Paragraph(
        "<code>Total Risk = Base_Risk (5) + Heuristic_Points (0-60) + ML_Anomaly_Weight (0-75)</code>",
        code_style
    ))
    elements.append(Paragraph("• <b>0 – 34 (LOW)</b>: Normal enterprise web browsing and DNS resolution.", bullet_style))
    elements.append(Paragraph("• <b>35 – 54 (MEDIUM)</b>: Suspicious packet or single-port probing.", bullet_style))
    elements.append(Paragraph("• <b>55 – 84 (HIGH)</b>: Active Port Scan or Volumetric Spike (Triggers Alert & Storage).", bullet_style))
    elements.append(Paragraph("• <b>85 – 100 (CRITICAL)</b>: Volumetric SYN Flood or Multi-Vector Reconnaissance.", bullet_style))

    # Section 7: GenAI Threat Copilot & MITRE ATT&CK
    elements.append(Paragraph("7. GenAI Incident Copilot & MITRE ATT&CK Mapping", h1_style))
    elements.append(Paragraph(
        "When an alert is flagged, the user can click <b>'Explain with AI'</b>. The AI Copilot immediately synthesizes:",
        body_style
    ))
    elements.append(Paragraph("1. <b>Plain-English Diagnostic Briefing:</b> Explains the attacker's motive and packet dynamics.", bullet_style))
    elements.append(Paragraph("2. <b>MITRE ATT&CK Framework Mapping:</b> Tags attacks with official industry techniques (e.g. <i>T1046: Network Service Discovery</i>, <i>T1498: Network Denial of Service</i>).", bullet_style))
    elements.append(Paragraph("3. <b>Automated Firewall Containment Scripts:</b> Provides 1-click copy commands for Windows PowerShell (<code>New-NetFirewallRule</code>) and Linux (<code>iptables -A INPUT -s IP -j DROP</code>).", bullet_style))

    # Section 8: Resume & Interview Section
    elements.append(Paragraph("8. Resume Points & Interview Talking Points", h1_style))
    elements.append(Paragraph("<b>How to List This Project on Your Resume:</b>", h2_style))
    
    resume_box = [
        [Paragraph("<b>CyberShield: AI-Powered Network Intrusion Detection & Incident Response System</b><br/>"
                   "<i>Python, FastAPI, Scikit-learn (Isolation Forest), React 19, Tailwind CSS, WebSockets, SQLAlchemy, Scapy</i><br/>"
                   "• Architected an end-to-end NIDS combining an unsupervised <b>Isolation Forest</b> ML model with a stateful heuristic engine to detect port scanning, DoS floods, and zero-day packet anomalies in real time.<br/>"
                   "• Developed a high-throughput <b>FastAPI</b> backend processing streaming packet flows over asynchronous <b>WebSockets</b>, computing dynamic 0-100 composite risk scores with sub-second latency.<br/>"
                   "• Integrated a <b>GenAI Security Copilot</b> mapping detected threats to the <b>MITRE ATT&CK Framework</b> (T1046, T1498) and auto-generating ready-to-execute Windows PowerShell and Linux IPtables firewall containment scripts.<br/>"
                   "• Engineered a responsive SOC dashboard using <b>React 19</b>, <b>Tailwind CSS</b>, and <b>Recharts</b> featuring real-time risk gauges, live packet inspection, and an attack simulator.",
                   callout_style)]
    ]
    t_res = Table(resume_box, colWidths=[7.0*inch])
    t_res.setStyle(TableStyle([
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
    ]))
    elements.append(t_res)

    elements.append(Spacer(1, 10))
    elements.append(Paragraph("<b>Top Interview Questions & How to Answer Them:</b>", h2_style))
    elements.append(Paragraph(
        "<b>Q: Why did you use Isolation Forest instead of a neural network?</b><br/>"
        "<i>Answer:</i> In network traffic, normal packets vastly outnumber attack packets (extreme class imbalance). Isolation Forest doesn't require labelled training data; it builds random decision trees where outliers isolate at much shallower tree depths than standard clusters. It is fast, explainable, and excels at discovering zero-day anomalies without overfitting.",
        body_style
    ))
    elements.append(Paragraph(
        "<b>Q: Why use WebSockets instead of REST polling for the dashboard?</b><br/>"
        "<i>Answer:</i> Traditional HTTP polling creates unnecessary server overhead and latency. Using WebSockets, the FastAPI backend maintains a persistent duplex connection, streaming packets and broadcasting alerts instantaneously the millisecond a threshold is crossed.",
        body_style
    ))

    doc.build(elements)
    print(f"PDF successfully generated at: {filename}")

if __name__ == "__main__":
    create_project_guide_pdf("CyberShield_NIDS_Complete_Project_Guide.pdf")
