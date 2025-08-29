# CVSS Calculator for Burp Suite

A modern Burp Suite extension that calculates CVSS v3.1 Base Scores with a clean, professional interface.

## Demo
https://github.com/user-attachments/assets/774b83d3-002d-4b03-ab88-ad01c41db543

## Description

This extension provides security researchers with an integrated CVSS calculator directly within Burp Suite. Calculate vulnerability severity scores without leaving your testing environment.

## Features

- CVSS v3.1 compliant base score calculation
- Clean, modern interface that matches Burp's theme
- Detailed results with severity ratings
- Standard CVSS vector string generation
- Real-time calculation with comprehensive breakdown

## Installation

1. Download the Python script
2. Open Burp Suite → Extensions → Add
3. Select "Python" as extension type
4. Load the script file
5. Access via the "CVSS Calculator" tab

## Usage

1. Select appropriate values for each CVSS metric using the dropdown menus
2. Click "Calculate CVSS Score"
3. View detailed results including:
   - Base score (0.0 - 10.0)
   - Severity rating (None/Low/Medium/High/Critical)
   - CVSS vector string
   - Individual metric breakdown

## Requirements

- Burp Suite (Professional or Community)
- Jython standalone JAR configured in Burp Suite

## CVSS Metrics

- **Attack Vector**: Network, Adjacent, Local, Physical
- **Attack Complexity**: Low, High  
- **Privileges Required**: None, Low, High
- **User Interaction**: None, Required
- **Scope**: Unchanged, Changed
- **Confidentiality Impact**: None, Low, High
- **Integrity Impact**: None, Low, High
- **Availability Impact**: None, Low, High

## Author

**Raunak Gupta**  
Security Researcher & Bug Bounty Hunter

## License

MIT License
