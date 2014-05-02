w3af_asm
========

F5 xml_f5asm plugin for w3af provides an output plugin that will export vulnerability into the F5 ASM XML import format. Scan results can then be uploaded to your F5 ASM and pre-populate your URL lists, as well as vulnerabilitys and remediations.

Installation
------------
Place the xml_f5asm.py file:
  $W3AF_HOME/w3af/plugins/output/

Configuration
-------------
The plugin has one configuration option:
  output_file: the ASM XML file to be written

Command line:
  output console,xml_f5asm
  output config xml_f5asm
  set output_file /tmp/f5asm.xml

Output
_______
The output is based on the generic_scanner.xsd that F5 provides. Similar to this:

  <?xml version="1.0" encoding="UTF-8"?>
  <scanner_vulnerabilities version="1399053867">
      <vulnerability>
          <attack_type>Cross-site Request Forgery</attack_type>
          <name>CSRF vulnerability</name>
          <url>http://www.bigsho.es/</url>
          <parameter>s=Search</parameter>
          <severity>High</severity>
          <threat>High</threat>
          <score>99</score>
          <status>Pending</status>
          <opened>no</opened>
      </vulnerability>
  </scanner_vulnerabilities>
  
The "attack_type" element is based on a hash table that matches up the w3af vulns to the pre-determined list of "attack types" that F5 ASM suupports. The default is a generic "Other Application Attacks"

The F5 ASM "Attack Types":
+ Information Leakage - SSN
+ Predictable Resource Location
+ XPath Injection
+ HTTP Response Splitting
+ Path Traversal
+ Cross-site Request Forgery
+ Path Traversal Apache Relative Path
+ SQL-Injection
+ Information Leakage - Credit Card
+ Cross Site Scripting (XSS)
+ Path Traversal Unix Relative Path
+ Path Traversal Windows Relative Path
+ Command Execution
+ Forceful Browsing
+ HTTP Request Smuggling Attack
+ Non-browser client
+ Denial of Service
+ Server Side Code Injection
+ Directory Indexing
+ Abuse of Functionality
+ Other Application Attacks
+ Other Application Activity
+ Injection Attempt
+ GWT Parser Attack
+ Parameter Tampering
+ Vulnerability Scan
+ HTTP Parser Attack
+ JSON Parser Attack
+ LDAP Injection
+ Remote File Include
+ Trojan/Backdoor/Spyware
+ Web Scraping
+ Malicious File Upload 
+ Brute Force Attack
+ XML Parser Attack
+ Authentication/Authorization Attacks
+ Session Hijacking
+ Information Leakage
+ Buffer Overflow 
+ Detection Evasion

Adjusting the attack type mapping is as easy as changing out the hash table that they are stored in.

