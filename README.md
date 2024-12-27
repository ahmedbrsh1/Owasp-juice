# Owasp-juice

Executive Summary
Purpose of the Test:
To identify and exploit vulnerabilities in the OWASP Juice Shop application, demonstrating common web application security flaws.

Key Findings:

Vulnerable to URL enumeration, leading to unauthorized admin path discovery.
Lack of rate-limiting enables brute-force attacks on admin credentials.
XSS vulnerabilities allow execution of arbitrary JavaScript.
SQL injection flaws could lead to data leakage or database manipulation.
Summary of Recommendations:

Implement proper access controls to secure hidden paths.
Enforce rate-limiting and account lockout mechanisms.
Validate and sanitize all user inputs to prevent XSS and SQL injection attacks.
Conduct regular security testing to identify and mitigate vulnerabilities.
Scope and Methodology
Scope:

Application: OWASP Juice Shop website.
Focus: Web pages, admin functionalities, and API endpoints.
Approach:

Black-box testing: No prior knowledge of the internal structure or source code.
Tools Used:

Burp Suite
Gobuster
Vulnerability Findings
1. Enumeration to Find Admin Path
Description:
The application exposes hidden paths that attackers can discover by analyzing the URL structure or using enumeration tools like ffuf.

Risk:
High. Discovery of the admin functionality can lead to further attacks like brute force or privilege escalation.

Potential Impact:
An attacker may gain access to sensitive admin features and exploit them to compromise the application.

Evidence:

Example: Enumerating paths such as /admin using ffuf revealed the admin login page.
Remediation Steps:

Restrict access to sensitive paths using authentication and authorization mechanisms.
Implement security through obscurity by randomizing or hiding admin URLs.
Vulnerability Findings
2. Brute Force on Admin Credentials
Description:
The admin login page lacks protections against brute-force attacks, enabling attackers to guess passwords using tools like Burp Suite.

Risk:
Critical. This vulnerability allows unauthorized access to admin accounts, granting full control of the application.

Potential Impact:
Compromise of administrative privileges can lead to data breaches, application misconfigurations, and more.

Evidence:

Using Burp Suite, we conducted a brute-force attack with the known email admin@juice-sh.op, which successfully cracked the password.
Remediation Steps:
![Brute Force](screenshots/Screenshot_2024-12-27_194424.png)

Implement rate-limiting and CAPTCHA mechanisms.
Introduce account lockout policies after repeated failed login attempts.

4. SQL Injection
Description:
The application does not properly sanitize inputs in certain fields, making it vulnerable to SQL injection.

Risk:
Critical. Exploiting this vulnerability allows attackers to manipulate the database, retrieve sensitive data, or disrupt operations.

Potential Impact:

Database compromise could lead to data leakage or the destruction of critical information.
Evidence:

Using ' OR 1=1 -- in input fields bypassed authentication and revealed sensitive data.
Remediation Steps:

Use parameterized queries or prepared statements.
Avoid dynamic SQL queries where possible.
Perform input validation and escaping.
Exploitation and Attack Simulation
Tools and Techniques Used:

Enumeration: Gobuster to discover hidden paths.
Brute Force: Hydra to guess admin credentials.
XSS: Manual payload injection via the search bar.
SQL Injection: Manual testing using SQL payloads.
Outcome and Impact:

Admin access gained through enumeration and brute force.
Arbitrary script execution using XSS.
Database manipulation via SQL injection.
Conclusion
Summary of Security Posture:
The OWASP Juice Shop exhibits multiple critical vulnerabilities, making it highly susceptible to exploitation.

Overall Risk Level:
Critical. Immediate attention is required to mitigate the identified vulnerabilities.

Next Steps for Remediation:

Address each identified vulnerability using the recommended fixes.
Regularly test the application for security weaknesses.
Educate developers on secure coding practices.
