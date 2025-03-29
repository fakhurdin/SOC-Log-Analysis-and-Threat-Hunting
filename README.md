# 🔍 SOC Log Analyzer & Threat Hunting

A powerful Python-based tool designed for Security Operations Centers (SOC) to analyze Windows Event Logs and Sysmon logs. This tool integrates MITRE ATT&CK techniques to identify Indicators of Compromise (IoCs) and potential security threats. It also features a Flask-based web interface for forensic evidence tracking.

## 🚀 Features

✅ **Windows Event Log (.evtx) and Sysmon log parsing**  
✅ **MITRE ATT&CK technique mapping for threat detection**  
✅ **IoC extraction (IP addresses, hashes, domains)**  
✅ **REST API for log analysis and forensic evidence tracking**  

## 📌 Installation

1. ## Clone the repository
   git clone https://github.com/yourusername/SOC-Log-Analyzer.git
   cd SOC-Log-Analyzer

    Install dependencies

pip install -r requirements.txt

Run the Flask server

    python soc_log_analyzer.py

🔬 Usage
1️⃣ Analyzing Windows Event Logs

    Convert .evtx logs into JSON and analyze threats.

    Extract IoCs (IP addresses, hashes, domains).

2️⃣ API Usage

    Start the Flask server.

    Send a POST request to analyze logs:

    curl -X POST http://localhost:5000/analyze -H "Content-Type: application/json" -d '{"log_file": "system.evtx"}'

📖 MITRE ATT&CK Integration

This tool leverages MITRE ATT&CK techniques to detect potential threats, making it an essential component for threat hunting and forensic investigations.
🛠️ Future Enhancements

    📊 Dashboard for real-time analysis

    📂 Database integration for log storage

    ⚡ Live monitoring of log files

🤝 Contributing

We welcome contributions! Feel free to submit pull requests or report issues.
📜 License

This project is licensed under the MIT License.

👨‍💻 Developed by: Fakhur ul din


This README provides clear setup instructions, 
