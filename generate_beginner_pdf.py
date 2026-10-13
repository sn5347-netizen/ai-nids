import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Canvas that adds clean page numbers and footer."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(40, 25, "CyberShield AI-NIDS • Complete Beginner Study Guide & Engineering Walkthrough")
        self.drawRightString(letter[0] - 40, 25, f"Page {self._pageNumber} of {page_count}")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(40, 35, letter[0] - 40, 35)
        self.restoreState()

def create_beginner_friendly_pdf(filename="CyberShield_NIDS_Beginner_Master_Guide.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0284c7'),
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=8,
        spaceAfter=3,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155'),
        spaceAfter=5
    )

    analogy_style = ParagraphStyle(
        'AnalogyStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor('#064e3b'),
        backColor=colors.HexColor('#ecfdf5'),
        borderPadding=6,
        spaceAfter=6
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor('#1e293b'),
        backColor=colors.HexColor('#f0f9ff'),
        borderPadding=6,
        spaceAfter=6
    )

    code_style = ParagraphStyle(
        'CodeSnippet',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0f172a'),
        backColor=colors.HexColor('#f1f5f9'),
        borderPadding=5,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'BulletText',
        parent=body_style,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    elements = []

    # Title Banner
    elements.append(Paragraph("🛡️ CyberShield: AI-Powered Network Intrusion Detection System", title_style))
    elements.append(Paragraph("The Beginner-to-Pro Master Guide: How It Works, Why It Works & Interview Secrets", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=8))

    # SECTION 1: Networking Basics with Simple Real-Life Analogies
    elements.append(Paragraph("1. Networking 101: Simple Everyday Analogies", h1_style))
    elements.append(Paragraph(
        "Before diving into code, let's understand how computer networks work using a simple apartment building analogy:",
        body_style
    ))
    
    analogies = [
        ("What is an IP Address?", "Think of an IP address like a home mailing address. Every computer connected to the internet has a unique IP (e.g. 192.168.1.100). When you browse a website, your computer sends letters from your IP to Google's IP."),
        ("What is a Port Number?", "Imagine an IP is an office building, and Ports are the different numbered doors inside. Door 80 & 443 are the front lobby for public websites. Door 22 is the secure basement server room. Door 53 is the office phone directory (DNS). There are 65,535 possible doors."),
        ("What is a Packet?", "Internet data cannot travel all at once. Big files are broken into tiny digital envelopes called 'Packets' (each with sender IP, destination IP, port, and a few hundred bytes of data)."),
        ("What is an Intrusion Detection System (NIDS)?", "A NIDS is like an intelligent security camera and guard stationed at the front gate. It inspects every single packet passing through the network, watches for suspicious behavior, and sounds the alarm before attackers can break in.")
    ]

    for term, desc in analogies:
        elements.append(Paragraph(f"<b>• {term}:</b> {desc}", analogy_style))

    # SECTION 2: What Attacks Do We Detect?
    elements.append(Paragraph("2. The Cyber Attacks We Detect (In Simple Words)", h1_style))
    
    attacks = [
        ("Port Scanning (The Doorknob Rattler)", "An attacker wants to find an unlocked door into your computer. In a Port Scan, the attacker quickly tries doors 21, 22, 23, 80, 443, and 3389 in rapid succession. Our system notices when one person touches 8+ different doors in 8 seconds and sounds the alarm."),
        ("Denial of Service - DoS (The Phone Jammer)", "Imagine 1,000 angry callers spamming a pizza shop's phone line simultaneously so real customers get a busy tone. In a DoS attack, an attacker spams 50+ packets per second to crash the server. Our system measures packet velocity and catches floods immediately."),
        ("Stealth Scans (NULL & XMAS Attacks)", "TCP packets normally carry communication flags (like 'Hello' = SYN or 'Goodbye' = FIN). Attackers sometimes craft illegal packets with NO flags (NULL scan) or ALL flags lit up like a Christmas tree (XMAS scan) to confuse basic firewalls. Our engine inspects flag combinations and catches them."),
        ("Zero-Day & Statistical Anomalies", "What if a hacker invents a brand new attack never seen before? Static rules will miss it. That is why we use Machine Learning (Isolation Forest) to catch any packet that doesn't look like normal, peaceful web traffic.")
    ]

    for title, exp in attacks:
        elements.append(Paragraph(f"<b>{title}:</b>", h2_style))
        elements.append(Paragraph(exp, body_style))

    # SECTION 3: The Machine Learning (Isolation Forest Explained for Beginners)
    elements.append(Paragraph("3. Machine Learning Deep-Dive: How Isolation Forest Works", h1_style))
    elements.append(Paragraph(
        "<b>The Crowd Metaphor:</b> Imagine you are in a room with 1,000 corporate accountants wearing dark business suits. Suddenly, someone walks in wearing a neon rainbow clown costume. How many questions do you need to ask to spot the clown? <i>Just one: 'Who has a rainbow wig?'</i> You isolate them instantly! But if you wanted to isolate one specific accountant, you would have to ask 50 questions (height, hair color, tie pattern, shoe size).",
        analogy_style
    ))
    elements.append(Paragraph(
        "<b>How the Algorithm Does This in Math:</b><br/>"
        "• <b>Normal Traffic</b> = The Accountants (HTTP web browsing, Google DNS queries). They look similar, so decision trees need many deep cuts to separate them.<br/>"
        "• <b>Malicious Traffic</b> = The Clown (Huge packet size, strange ports, rapid burst rates). Decision trees isolate them with very few splits near the root.<br/>"
        "• When an anomaly is isolated quickly with few splits, the algorithm gives it a <b>negative outlier score</b>, triggering an AI anomaly alert!",
        body_style
    ))

    # SECTION 4: The 12 Clues Given to the AI
    elements.append(Paragraph("4. The 12 Clues Extracted from Every Packet", h1_style))
    elements.append(Paragraph("Every packet that enters our system is converted into 12 numerical clues (features):", body_style))

    clues_table = [
        [Paragraph("<b>Clue #</b>", body_style), Paragraph("<b>Feature Name</b>", body_style), Paragraph("<b>What It Tells the AI</b>", body_style)],
        [Paragraph("1", body_style), Paragraph("packet_length", body_style), Paragraph("Byte size. Huge packets indicate data theft; tiny packets indicate ping scans.", body_style)],
        [Paragraph("2, 3, 4", body_style), Paragraph("proto_tcp, udp, icmp", body_style), Paragraph("Is it TCP (web/apps), UDP (video/DNS), or ICMP (network pings)?", body_style)],
        [Paragraph("5", body_style), Paragraph("is_well_known_port", body_style), Paragraph("1 if standard public port (like 80 or 443), 0 if a weird high port.", body_style)],
        [Paragraph("6", body_style), Paragraph("dst_port_norm", body_style), Paragraph("Destination port number scaled between 0.0 and 1.0.", body_style)],
        [Paragraph("7, 8, 9, 10", body_style), Paragraph("SYN, ACK, FIN, RST", body_style), Paragraph("TCP handshake flags. SYN=connecting, ACK=talking, FIN=closing, RST=resetting.", body_style)],
        [Paragraph("11", body_style), Paragraph("packet_rate", body_style), Paragraph("Speed: How many packets this sender sent in the last 3 seconds (detects floods).", body_style)],
        [Paragraph("12", body_style), Paragraph("port_diversity", body_style), Paragraph("How many different port doors this sender rattled in 8 seconds (detects scans).", body_style)],
    ]
    t_clues = Table(clues_table, colWidths=[0.6*inch, 1.8*inch, 4.6*inch])
    t_clues.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    elements.append(t_clues)
    elements.append(Spacer(1, 8))

    # SECTION 5: Step-by-Step Chronology (What Happens Behind the Scenes)
    elements.append(Paragraph("5. Step-by-Step: What Happens When You Click 'Port Scan'?", h1_style))
    steps = [
        "<b>Step 1 (User Action):</b> You click the 'Port Scan' button on the React dashboard in your browser.",
        "<b>Step 2 (API Call):</b> React sends an HTTP POST request to <code>http://127.0.0.1:8000/api/simulate</code>.",
        "<b>Step 3 (Traffic Injection):</b> <code>traffic_simulator.py</code> fires 16 rapid TCP SYN packets targeting ports 21, 22, 23, 80, 443, 3389.",
        "<b>Step 4 (Feature Extraction):</b> <code>features.py</code> measures the speed (>15 pps) and unique ports (12 unique doors) and builds the 12-number vector.",
        "<b>Step 5 (Dual Brain Inspection):</b><br/>"
        "  • <i>Heuristic Rule:</i> Sees 12 ports in 8s ➔ triggers 'Port Scanning Attempt' (+55 risk points).<br/>"
        "  • <i>Isolation Forest:</i> Isolates the rapid SYN burst ➔ flags statistical anomaly (+35 risk points).",
        "<b>Step 6 (Risk Scoring):</b> Combines base + heuristic + ML points = <b>90.0 / 100 Risk Score (CRITICAL)</b>.",
        "<b>Step 7 (Database Storage):</b> <code>alert_manager.py</code> saves the alert to the SQLite database (<code>nids.db</code>).",
        "<b>Step 8 (Live WebSocket Push):</b> The backend broadcasts the alert over <code>ws://localhost:8000/ws/traffic</code>. React receives it and animates the row onto your screen instantly with zero page reload!",
        "<b>Step 9 (AI Copilot):</b> You click 'Explain with AI'. The AI Copilot tags it with <b>MITRE ATT&CK T1046</b>, explains it in plain English, and writes a 1-click Windows PowerShell command to block the attacker."
    ]
    for s in steps:
        elements.append(Paragraph(f"• {s}", bullet_style))

    # SECTION 6: Project Folder Guide
    elements.append(Paragraph("6. Project Folders Explained in Plain English", h1_style))
    folder_data = [
        [Paragraph("<b>File / Folder</b>", body_style), Paragraph("<b>What It Does (Beginner Friendly)</b>", body_style)],
        [Paragraph("<code>backend/app/main.py</code>", body_style), Paragraph("The server entrance. Runs FastAPI and keeps the live WebSocket pipe open.", body_style)],
        [Paragraph("<code>backend/app/ml/detector.py</code>", body_style), Paragraph("The chief security officer. Runs both the ML model and port scan/DoS rules.", body_style)],
        [Paragraph("<code>backend/app/engine/ai_copilot.py</code>", body_style), Paragraph("The AI incident assistant. Maps threats to MITRE ATT&CK and writes firewall rules.", body_style)],
        [Paragraph("<code>backend/app/models.py</code>", body_style), Paragraph("The database blueprint. Defines how alerts and packet logs are stored in SQLite.", body_style)],
        [Paragraph("<code>frontend/src/App.jsx</code>", body_style), Paragraph("The visual command center (React). Renders the dark cyber UI, gauges, tables, and charts.", body_style)],
        [Paragraph("<code>start.bat</code>", body_style), Paragraph("1-click magic starter. Double-click it to start both backend and frontend servers together.", body_style)],
    ]
    t_folders = Table(folder_data, colWidths=[2.2*inch, 4.8*inch])
    t_folders.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    elements.append(t_folders)
    elements.append(Spacer(1, 8))

    # SECTION 7: How to Launch Anytime
    elements.append(Paragraph("7. How to Start the Project Anytime", h1_style))
    elements.append(Paragraph(
        "<b>1-Click Method:</b> Open folder <code>C:\\Users\\shiva\\OneDrive\\Desktop\\ai-nids</code> and double-click <b><code>start.bat</code></b>.<br/>"
        "<b>Browser Address:</b> Open Chrome or Edge and go to <b><u>http://localhost:5173</u></b>.",
        callout_style
    ))

    # SECTION 8: Resume & Interview Gold
    elements.append(Paragraph("8. Resume Section & How to Explain in Interviews", h1_style))
    elements.append(Paragraph("<b>Copy-Paste for Resume:</b>", h2_style))
    
    res_text = (
        "<b>CyberShield: AI-Powered Network Intrusion Detection & Incident Response System</b><br/>"
        "<i>Python, FastAPI, Scikit-learn (Isolation Forest), React 19, Tailwind CSS, WebSockets, SQLAlchemy, Scapy</i><br/>"
        "• Engineered a real-time NIDS combining an unsupervised <b>Isolation Forest ML model</b> with stateful heuristic rules to detect port scans, volumetric DoS floods, and zero-day anomalies with sub-second latency.<br/>"
        "• Built an asynchronous <b>FastAPI</b> backend streaming live telemetry over full-duplex <b>WebSockets</b> to a responsive <b>React 19</b> SOC dashboard with dynamic 0-100 risk scoring.<br/>"
        "• Integrated an <b>AI Threat Copilot</b> mapping detections to the <b>MITRE ATT&CK Framework</b> (T1046, T1498) and auto-generating 1-click Windows PowerShell and Linux IPtables firewall quarantine scripts."
    )
    elements.append(Paragraph(res_text, callout_style))

    elements.append(Paragraph("<b>Top 3 Interview Questions & Answers:</b>", h2_style))
    elements.append(Paragraph(
        "<b>1. What is this project in one sentence?</b><br/>"
        "<i>Answer:</i> CyberShield is a real-time network defense system that uses unsupervised machine learning and heuristic rules to detect cyberattacks as packets travel across a network, visualize them on a live SOC dashboard, and automatically generate firewall containment scripts.",
        body_style
    ))
    elements.append(Paragraph(
        "<b>2. Why did you use Isolation Forest instead of a standard classifier?</b><br/>"
        "<i>Answer:</i> Supervised models need pre-labelled attack data and fail on brand-new zero-day exploits. Normal web traffic represents 99.9% of flows. Isolation Forest is unsupervised: it isolates outliers at shallow decision tree depths based on structural variance without needing pre-existing attack signatures.",
        body_style
    ))
    elements.append(Paragraph(
        "<b>3. What was the hardest engineering challenge?</b><br/>"
        "<i>Answer:</i> Coordinating asynchronous streaming with stateful detection. We needed to calculate rolling packet velocity (PPS) and unique destination port diversity across sliding time windows in real time, score each packet with ML, persist alerts to SQLite, and broadcast them over WebSockets to React with zero UI lag.",
        body_style
    ))

    doc.build(elements, canvasmaker=NumberedCanvas)
    print(f"Beginner master guide generated at: {filename}")

if __name__ == "__main__":
    create_beginner_friendly_pdf()
