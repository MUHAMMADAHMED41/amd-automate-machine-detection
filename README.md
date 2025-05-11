# amd-automate-machine-detection
AMD2 is a Python for Asterisk-based telephony systems, such as VICIdial, to perform Answering Machine Detection (AMD) and honeypot detection. It analyzes call audio via a WebSocket service to classify calls as HUMAN, MACHINE, or HONEYPOT, updates a MySQL database with call outcomes, and sets Asterisk variables for dynamic call routing


AMD2 - Asterisk AGI Script for Answering Machine and Honeypot Detection

Overview
--------
AMD2 is a Python 3.4 script designed for Asterisk-based telephony systems, such as VICIdial, to perform Answering Machine Detection (AMD) and honeypot detection. It analyzes call audio via a WebSocket service to classify calls as HUMAN, MACHINE, or HONEYPOT, updates a MySQL database with call outcomes, and sets Asterisk variables for dynamic call routing. This script is ideal for call centers aiming to optimize outbound dialing and avoid robocall traps.

Features
--------
- Answering Machine Detection (AMD): Classifies calls as:
  - HUMAN: Live person answering.
  - MACHINE: Answering machine or voicemail.
  - HONEYPOT: Systems designed to trap robocalls.
- WebSocket Integration: Sends audio chunks to a remote server (ws://api.amdy.io:2700) for real-time analysis.
- Database Updates: Logs call outcomes in VICIdial's MySQL database (vicidial_log and vicidial_list tables) for honeypot detection.
- Asterisk Integration: Sets AGI variables (AMDSTATUS, AMDCAUSE, AMDSTATS) to influence call routing in the dialplan.
- Robust Error Handling: Gracefully handles empty AGI variables, network errors, and database issues.
- Detailed Logging: Writes execution details to /var/log/amd/amd_YYYYMMDD.log for debugging.
- Python 3.4 Compatibility: Uses .format() for string formatting, ensuring compatibility with older Python versions.
- Secure SQL Queries: Uses parameterized queries to prevent SQL injection.

Prerequisites
-------------
- Asterisk server with VICIdial installed.
- Python 3.4.
- MySQL database with VICIdial schema (vicidial_log, vicidial_list tables).
- Python libraries: pyst2, pymysql, websocket-client.
- Network access to ws://api.amdy.io:2700.

Usage
-----
1. Place amd2.py in /var/lib/asterisk/agi-bin/.
2. Configure the Asterisk dialplan to call AGI(amd2.py).
3. Ensure MySQL credentials are set in /etc/astguiclient.conf.
4. Test with a call and check logs in /var/log/amd/.

For detailed setup, see installation.txt.

Contributing
------------
Contributions are welcome! Please submit pull requests or issues on GitHub.

License
-------
MIT License (see LICENSE file, if included).

Contact
-------
For issues, open a ticket on GitHub or contact the repository maintainer.
