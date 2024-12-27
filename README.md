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
2. Brute Force on Admin Credentials
Description:
The admin login page lacks protections against brute-force attacks, enabling attackers to guess passwords using tools like Hydra.

Risk:
Critical. This vulnerability allows unauthorized access to admin accounts, granting full control of the application.

Potential Impact:
Compromise of administrative privileges can lead to data breaches, application misconfigurations, and more.

Evidence:

Using Hydra with admin@juice-sh.op, brute-force testing successfully cracked the password.
Remediation Steps:

Implement rate-limiting and CAPTCHA mechanisms.
Introduce account lockout policies after repeated failed login attempts.
3. XSS in Product Search
Description:
The product search feature fails to sanitize user input, allowing the execution of malicious scripts.

Risk:
High. Cross-Site Scripting can be used to steal session cookies, redirect users, or conduct phishing attacks.

Potential Impact:
Exploitation of XSS can compromise user data and reduce trust in the application.

Evidence:

Inputting <script>alert('XSS')</script> in the search bar resulted in an alert pop-up.
Remediation Steps:

Validate and sanitize all user inputs.
Use Content Security Policy (CSP) headers to mitigate XSS risks.
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
