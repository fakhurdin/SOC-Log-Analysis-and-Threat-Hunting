import os
import json
import pandas as pd
from evtx import PyEvtxParser
from mitreattack.stix20 import MitreAttackData
import re
from flask import Flask, request, jsonify

class SOCLogAnalyzer:
    def __init__(self, log_path):
        self.log_path = log_path
        self.iocs = self.load_mitre_attck()
    
    def load_mitre_attck(self):
        """Load MITRE ATT&CK techniques related to IoCs"""
        attack_data = MitreAttackData("enterprise-attack.json")
        return {technique.id: technique.name for technique in attack_data.get_techniques()}
    
    def parse_evtx(self):
        """Parse Windows Event Log (.evtx) files"""
        logs = []
        with PyEvtxParser(self.log_path) as parser:
            for record in parser.records_json():
                logs.append(json.loads(record['data']))
        return pd.DataFrame(logs)
    
    def parse_sysmon(self, sysmon_log_path):
        """Parse Sysmon logs in JSON format"""
        with open(sysmon_log_path, 'r') as file:
            logs = json.load(file)
        return pd.DataFrame(logs['Events'])
    
    def analyze_logs(self, df):
        """Analyze logs for potential threats based on MITRE ATT&CK techniques"""
        df['Suspicious'] = df['EventID'].apply(lambda x: x in self.iocs)
        return df[df['Suspicious']]
    
    def extract_iocs(self, df):
        """Extract potential IoCs from logs"""
        ioc_patterns = {
            'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'hash': re.compile(r'\b[A-Fa-f0-9]{64}\b'),
            'domain': re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        }
        extracted_iocs = {key: df['Message'].str.extract(pattern) for key, pattern in ioc_patterns.items()}
        return extracted_iocs


app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    log_file = data.get("log_file")
    analyzer = SOCLogAnalyzer(log_file)
    logs_df = analyzer.parse_evtx()
    suspicious_logs = analyzer.analyze_logs(logs_df)
    iocs = analyzer.extract_iocs(suspicious_logs)
    return jsonify({"suspicious_logs": suspicious_logs.to_dict(), "iocs": iocs})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
