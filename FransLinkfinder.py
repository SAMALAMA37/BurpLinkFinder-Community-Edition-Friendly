#
#  BurpLinkFinder - Find links within JS files.
#  Community Edition Friendly Version (with Scope & Redundancy Check)
#
#  Copyright (c) 2022 Frans Hendrik Botes
#  Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex
#
#  --- Corrected and Refactored Version (Scope Check Removed) ---
#
from burp import IBurpExtender, IHttpListener, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
import cgi
from os import path
from javax import swing
from java.awt import Font, Color, EventQueue
from java.lang import Runnable
from threading import Thread
from jarray import array
import urlparse, threading

try:
    import queue
except ImportError:
    import Queue as queue

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# --- Global Parameters ---
JSExclusionList = ['jquery', 'google-analytics', 'gpt.js', 'modernizr', 'gtm', 'fbevents']

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinderCE")

        # --- Sets for efficient duplicate checking ---
        self.processed_urls = set()
        self.mapped_urls_set = set()
        self.found_filenames_set = set()
        
        self.threads = []
        self.initUI()
        
        # Customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(self._splitpane2)
        callbacks.customizeUiComponent(self.logPane)
        callbacks.customizeUiComponent(self.filesPane)
        callbacks.customizeUiComponent(self.mapPane)
        callbacks.customizeUiComponent(self._parentPane)
        
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # Register as an HTTP listener
        callbacks.registerHttpListener(self)
        
        callbacks.printOutput("BurpJS LinkFinder v2 (Community Edition) loaded.")
        callbacks.printOutput("Copyright (c) 2022 Frans Hendrik Botes")
        self.outputTxtArea.setText("BurpJS LinkFinder (Community Edition) loaded.\nCopyright (c) 2022 Frans Hendrik Botes\n")

    def initUI(self):
        self._parentPane = swing.JTabbedPane()
        self._splitpane = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self._splitpane.setDividerLocation(800)
        self._splitpane2 = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)
        self._splitpane2.setDividerLocation(300)
        
        # --- Log Panel ---
        self.logPanel = swing.JPanel()
        self.outputLabel = swing.JLabel("LinkFinder Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.outputLabel.setForeground(Color(255, 102, 52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export", actionPerformed=self.exportLog)
        
        layout = swing.GroupLayout(self.logPanel)
        self.logPanel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addComponent(self.outputLabel)
            .addComponent(self.logPane)
            .addGroup(layout.createSequentialGroup().addComponent(self.clearBtn).addComponent(self.exportBtn))
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.outputLabel)
            .addComponent(self.logPane)
            .addGroup(layout.createParallelGroup().addComponent(self.clearBtn).addComponent(self.exportBtn))
        )
        
        # --- Filenames Panel ---
        self.filePanel = swing.JPanel()
        self.fileNamesLabel = swing.JLabel("Filenames:")
        self.fileNamesLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.fileNamesLabel.setForeground(Color(255, 102, 52))
        self.filesPane = swing.JScrollPane()
        self.filesTxtArea = swing.JTextArea()
        self.filesTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.filesTxtArea.setLineWrap(True)
        self.filesPane.setViewportView(self.filesTxtArea)
        self.clearFilesBtn = swing.JButton("Clear", actionPerformed=self.clearFilesLog)
        
        layoutf = swing.GroupLayout(self.filePanel)
        self.filePanel.setLayout(layoutf)
        layoutf.setAutoCreateGaps(True)
        layoutf.setAutoCreateContainerGaps(True)
        layoutf.setHorizontalGroup(layoutf.createParallelGroup().addComponent(self.fileNamesLabel).addComponent(self.filesPane).addComponent(self.clearFilesBtn))
        layoutf.setVerticalGroup(layoutf.createSequentialGroup().addComponent(self.fileNamesLabel).addComponent(self.filesPane).addComponent(self.clearFilesBtn))
        
        # --- Mapped Panel ---
        self.mapPanel = swing.JPanel()
        self.mapLabel = swing.JLabel("Mapped Endpoints:")
        self.mapLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.mapLabel.setForeground(Color(255, 102, 52))
        self.mapPane = swing.JScrollPane()
        self.mapTxtArea = swing.JTextArea()
        self.mapTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.mapTxtArea.setLineWrap(True)
        self.mapPane.setViewportView(self.mapTxtArea)
        self.clearMapBtn = swing.JButton("Clear", actionPerformed=self.clearMapLog)
        self.mapMapBtn = swing.JButton("Add to Site Map", actionPerformed=self.mapMaps)

        layoutm = swing.GroupLayout(self.mapPanel)
        self.mapPanel.setLayout(layoutm)
        layoutm.setAutoCreateGaps(True)
        layoutm.setAutoCreateContainerGaps(True)
        layoutm.setHorizontalGroup(layoutm.createParallelGroup().addComponent(self.mapLabel).addComponent(self.mapPane).addGroup(layoutm.createSequentialGroup().addComponent(self.clearMapBtn).addComponent(self.mapMapBtn)))
        layoutm.setVerticalGroup(layoutm.createSequentialGroup().addComponent(self.mapLabel).addComponent(self.mapPane).addGroup(layoutm.createParallelGroup().addComponent(self.clearMapBtn).addComponent(self.mapMapBtn)))

        self._splitpane.setLeftComponent(self.logPanel)
        self._splitpane2.setTopComponent(self.filePanel)
        self._splitpane2.setBottomComponent(self.mapPanel)
        self._splitpane.setRightComponent(self._splitpane2)
        self._parentPane.addTab("Main", self._splitpane)

    def getTabCaption(self):
        return "BurpJSLinkFinder"

    def getUiComponent(self):
        return self._parentPane

    def clearLog(self, event):
        self.outputTxtArea.setText("BurpJS LinkFinder (Community Edition) loaded.\nCopyright (c) 2022 Frans Hendrik Botes\n")
        self.processed_urls.clear()

    def clearFilesLog(self, event):
        self.filesTxtArea.setText("")
        self.found_filenames_set.clear()

    def clearMapLog(self, event):
        self.mapTxtArea.setText("")
        self.mapped_urls_set.clear()

    def exportLog(self, event):
        chooseFile = swing.JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        if ret == swing.JFileChooser.APPROVE_OPTION:
            filename = chooseFile.getSelectedFile().getCanonicalPath()
            self.callbacks.printOutput("\n" + "Exporting to: " + filename)
            try:
                with open(filename, 'w') as f:
                    f.write(self.outputTxtArea.getText())
            except IOError as e:
                self.callbacks.printError("Error writing to file: " + str(e))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        url = messageInfo.getUrl()
        url_str = str(url)

        # Check if the URL has already been processed
        # The scope check has been removed as per the user's request.
        if url_str in self.processed_urls:
            return

        response = messageInfo.getResponse()
        if not response:
            return

        responseInfo = self.helpers.analyzeResponse(response)
        mime_type = responseInfo.getStatedMimeType().lower()
        
        # Check if it's a JS or JSON file
        if 'javascript' in mime_type or 'json' in mime_type or url_str.endswith(('.js', '.json')):
            
            # Add to processed set before analysis
            self.processed_urls.add(url_str)
            
            # Exclude common JS libraries
            if any(x in url_str for x in JSExclusionList):
                self.callbacks.printOutput("\n" + "[-] URL excluded: " + url_str)
                return
            
            # THREADING FIX: Safely update the UI
            EventQueue.invokeLater(Run(lambda: self.outputTxtArea.append("\n" + "[+] Analyzing: " + url_str)))
            
            try:
                linkA = linkAnalyse(messageInfo, self.callbacks, self.helpers)
                issueText = linkA.analyseURL()
                
                for issue in issueText:
                    link = issue['link']
                    # THREADING FIX: Safely update the UI
                    EventQueue.invokeLater(Run(lambda: self.outputTxtArea.append("\n" + "\t" + link)))
                    
                    # Construct full URL
                    fullURL = urlparse.urljoin(url_str, link) if not linkA.valcheckFullURL(link) else link
                    
                    # PERFORMANCE FIX: Use set for efficient duplicate check
                    if fullURL not in self.mapped_urls_set:
                        self.mapped_urls_set.add(fullURL)
                        # THREADING FIX: Safely update the UI
                        EventQueue.invokeLater(Run(lambda: self.mapTxtArea.append("\n" + fullURL)))
                    
                    # Extract and check filename
                    filNam = path.basename(link.split('?')[0])
                    if linkA.isNotBlank(filNam) and linkA.checkValidFile(filNam):
                         # PERFORMANCE FIX: Use set for efficient duplicate check
                        if filNam not in self.found_filenames_set:
                            self.found_filenames_set.add(filNam)
                            # THREADING FIX: Safely update the UI
                            EventQueue.invokeLater(Run(lambda: self.filesTxtArea.append("\n" + filNam)))

            except Exception as e:
                self.callbacks.printError("Error in processHttpMessage: " + str(e))

    def mapMaps(self, event):
        self.q = queue.Queue()
        get_all_urls = self.mapTxtArea.getText()
        urls_list = list(set(get_all_urls.split('\n')))

        for url in urls_list:
            url = url.strip()
            if url:
                self.q.put(url)

        for _ in range(10): # Start 10 worker threads
            t = threading.Thread(target=self.ProcessQueue)
            self.threads.append(t)
            t.start()

    def ProcessQueue(self):
        while not self.q.empty():
            try:
                each_url = self.q.get(timeout=1)
                self.ProcessURL(each_url)
                self.q.task_done()
            except queue.Empty:
                return # Queue is empty
        
    def URL_SPLITTER(self, url):
        URL_SPLIT = str(url).split("://", 1)
        URL_PROTOCAL = URL_SPLIT[0]
        URL_PORT = 443 if URL_PROTOCAL == 'https' else 80
        URL_HOSTNAME_PATH = URL_SPLIT[1]
        URL_HOSTNAME = URL_HOSTNAME_PATH.split('/')[0].split('?')[0]
        if ':' in URL_HOSTNAME:
            URL_HOSTNAME, URL_PORT_STR = URL_HOSTNAME.split(':', 1)
            URL_PORT = int(URL_PORT_STR)
        URL_HOST_SERVICE = self.helpers.buildHttpService(URL_HOSTNAME, URL_PORT, URL_PROTOCAL == 'https')
        return URL_HOST_SERVICE

    def ProcessURL(self, url):
        if url.startswith(('http://', 'https://')):
            try:
                parsed_url = URL(url)
                # NOTE: A scope check is kept here intentionally. This prevents the "Add to Site Map"
                # feature from sending requests to out-of-scope targets, which is usually undesirable.
                if not self.callbacks.isInScope(parsed_url):
                    return
            
                URL_HOST_SERVICE = self.URL_SPLITTER(url)
                request = self.helpers.buildHttpRequest(parsed_url)
                resp = self.callbacks.makeHttpRequest(URL_HOST_SERVICE, request)

                # addToSiteMap is thread-safe
                if resp:
                    self.callbacks.addToSiteMap(resp)
            except Exception as e:
                self.callbacks.printError("Error processing URL for site map: {} ({})".format(url, e))

    def extensionUnloaded(self):
        self.callbacks.printOutput("BurpJS LinkFinder v2 unloaded")
        return

class linkAnalyse():
    
    def __init__(self, reqres, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.reqres = reqres
        
    regex_str = """
      (?:"|')                               # Start newline delimiter
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
        |
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
        |
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/.]{1,}                # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
        |
        ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
        [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
        (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
        |
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)        # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
      )
      (?:"|')                               # End newline delimiter
    """     

    def parser_file(self, content, regex_str, no_dup=1):
        regex = re.compile(regex_str, re.VERBOSE)
        items = [{"link": m.group(1)} for m in re.finditer(regex, content)]
        if no_dup:
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            return no_dup_items
        return items

    def analyseURL(self):      
        responseBytes = self.reqres.getResponse()
        if responseBytes:
            decoded_resp = self.helpers.bytesToString(responseBytes)
            return self.parser_file(decoded_resp, self.regex_str)
        return []
    
    def checkValidFile(self, fileNam):
        # REGEX FIX: Corrected regex to validate filenames with extensions.
        regexFile = r'^[\w\s.-]+\.[a-zA-Z0-9]{2,10}$'
        return fileNam and fileNam.strip() and bool(re.search(regexFile, fileNam))
       
    def isNotBlank(self, myString):
        return myString and myString.strip()
    
    def valcheckFullURL(self, myString):
        return myString.lower().startswith(('http:', 'https:'))

# NOTE: The SRI class is defined but not used in the current version of the extension.
# It is intended for creating custom Burp Scanner issues.
class SRI(IScanIssue):
    def __init__(self, reqres, helpers, callbacks, links, full_urls, highlights):
        self.helpers = helpers
        self.callbacks = callbacks
        self.links = sorted(list(set(links)))
        self.full_urls = sorted(list(set(full_urls)))
        al = ArrayList()
        for h in highlights:
            al.add(array([h[0], h[1]], 'i'))
        self.reqres = self.callbacks.applyMarkers(reqres, None, al)
        self.issue_detail = "Burp Scanner has analysed this JS file and has discovered the following link values: <ul>\n"
        for link in self.links:
            self.issue_detail += "<li>{}</li>\n".format(cgi.escape(link))
        self.issue_detail += "</ul>The following full normalized URLs were generated from the discovered link values: <ul>\n"
        for url in self.full_urls:
            self.issue_detail += "<li>{}</li>\n".format(cgi.escape(url))
        self.issue_detail += "</ul>"
    def getHost(self): return self.reqres.getHost()
    def getPort(self): return self.reqres.getPort()
    def getProtocol(self): return self.reqres.getProtocol()
    def getUrl(self): return self.reqres.getUrl()
    def getIssueName(self): return "Linkfinder Analysed JS files"
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return "Information"
    def getConfidence(self): return "Certain"
    def getIssueBackground(self): return "JS files can hold links to other parts of web applications. This extension passively finds them and reports them for further investigation."
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self.issue_detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self.reqres]
    def getHttpService(self): return self.reqres.getHttpService()
