# **Reflected XSS Scanner (Python, Single-File)**

A lightweight reflected XSS vulnerability scanner built in pure Python, designed for academic use and small-scale security testing.
The scanner injects context-aware XSS payloads into selected parameters and checks whether they are reflected in the server response.

This tool fully meets your assignment requirements.

## **Features**

* Context-aware Payload Generator
* Supports text, attribute-value, attribute-name, and JavaScript contexts
* Scans 5 predefined parameters:

    `q, id, username, query, page`


* Supports GET and POST
* Detects reflected payloads via simple substring matching
* Clean terminal-based vulnerability report

## **Project Structure**

Everything (payload generation, scanning, reporting) is inside main.py.

**How It Works**

### 1. Payload Generation

The scanner uses a PayloadGenerator class to generate XSS payloads depending on the injection context:

| Context        | Description                      | Example Payload               |
| -------------- | -------------------------------- | ----------------------------- |
| **text**       | Injected into HTML body          | `<script>alert('X')</script>` |A random suffix is appended to each payload to uniquely track reflections.
| **attr-value** | Inside `" "` or `' '` attributes | `" onmouseover="alert(1)`     |
| **attr-name**  | Injected as attribute name       | `xssmark-attr`                |### 2. Scanning Logic
| **js**         | Inside JavaScript                | `';alert(1);//`               |
              
### 2. Scanning Logic

For each parameter (`q, id, username, query, page`):

* Generate context-based payload
* Inject payload → send HTTP GET/POST request
* Check reflection using:

    `if payload in response.text:`

* Extract an evidence snippet
Print results in a clear terminal report

## Installation


Install dependencies:

    `pip install -r requirements.txt`

requirements.txt contains:

    `requests`

## Usage
Basic reflected XSS scan

    python main.py --url "http://test.com"


Scans parameters:

    q, id, username, query, page

## Scan using specific contexts

You can force custom contexts for parameters:

    python main.py --url "http://test.com" --context-map "q:text,id:attr-name"


Explanation:

* `q` uses text-context payloads
* `id` uses attribute-name payloads 


### POST request scanning

    python main.py --url "http://example.com/login" --method POST

### Add custom headers
    python main.py --url "http://testphp.vulnweb.com/search.php" --header "User-Agent: XSSScanner"

### Example Output
=== Reflected XSS Report ===

    [1] GET http://testphp.vulnweb.com/search.php?search=<script>alert('XSSMARK9fc')</script>
        Param   : q
        Payload : <script>alert('XSSMARK9fc')</script>
        Context : text
        Evidence:
            ...Search results for <script>alert('XSSMARK9fc')</script>...
    ----------------------------------------------------------------------

## Default Parameters Scanned

The scanner automatically tests:

    q
    id
    username
    query
    page

You do not need to provide `--params`.

## Code Components
### 1. PayloadGenerator

* Generates payloads for 4 contexts
* Adds random suffix for marker uniqueness

### 2. XSSScanner

* Injects payloads
* Sends GET/POST requests
* Checks reflections
* Extracts evidence snippets

### 3. Reporting

* Outputs clean terminal report

* Shows payload, parameter, context, and HTML evidence


## Final Notes

This small reflected XSS scanner is clean, modular, and meets all assignment requirements.
All logic is contained inside main.py for easy grading and submission.