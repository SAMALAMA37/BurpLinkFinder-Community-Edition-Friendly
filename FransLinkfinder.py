#
#  BurpLinkFinder - Find links within JS files.
#  Community Edition Friendly Version (with Scope & Redundancy Check)
#
#  Copyright (c) 2022 Frans Hendrik Botes
#  Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex
#
from burp import IBurpExtender, IHttpListener, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
import cgi
from os import path
from javax import swing
from java.awt import Font, Color
from threading import Thread
from jarray import array
from java.awt import EventQueue
from java.lang import Runnable
import urlparse,threading
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

# Needed params
JSExclusionList = ['jquery', 'google-analytics','gpt.js','modernizr','gtm','fbevents']

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinderCE")
        callbacks.issueAlert("BurpJSLinkFinderCE Passive Scanner enabled")

        # Register as an HTTP listener
        callbacks.registerHttpListener(self)
        
        # <<< --- FIX: Set to store URLs that have been processed --- >>>
        self.processed_urls = set()
        
        self.threads = []
        self.initUI()
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(self._splitpane2)
        callbacks.customizeUiComponent(self.logPane)
        callbacks.customizeUiComponent(self.filesPane)
        callbacks.customizeUiComponent(self.mapPane)
        callbacks.customizeUiComponent(self._parentPane)
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        callbacks.printOutput("BurpJS LinkFinder v2 (Community Edition) loaded.")
        callbacks.printOutput("Copyright (c) 2022 Frans Hendrik Botes")
        self.outputTxtArea.setText("BurpJS LinkFinder (Community Edition) loaded." + "\n" + "Copyright (c) 2022 Frans Hendrik Botes" + "\n")

    def initUI(self):
        self._parentPane = swing.JTabbedPane()
        self._splitpane = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self._splitpane.setDividerLocation(800)
        self._splitpane2 = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)
        self._splitpane2.setDividerLocation(300)
        self.logPanel = swing.JPanel()
        self.outputLabel = swing.JLabel("LinkFinder Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()
        layout = swing.GroupLayout(self.logPanel)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.logPanel.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )
        self.filePanel = swing.JPanel()
        self.fileNamesLabel = swing.JLabel("Filenames:")
        self.fileNamesLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.fileNamesLabel.setForeground(Color(255,102,52))
        self.filesPane = swing.JScrollPane()
        self.filesTxtArea = swing.JTextArea()
        self.filesTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.filesTxtArea.setLineWrap(True)
        self.filesPane.setViewportView(self.filesTxtArea)
        self.clearFilesBtn = swing.JButton("Clear", actionPerformed=self.clearFilseLog)
        layoutf = swing.GroupLayout(self.filePanel)
        layoutf.setAutoCreateGaps(True)
        layoutf.setAutoCreateContainerGaps(True)
        self.filePanel.setLayout(layoutf)
        layoutf.setHorizontalGroup(
            layoutf.createParallelGroup()
            .addGroup(layoutf.createSequentialGroup()
                .addGroup(layoutf.createParallelGroup()
                    .addComponent(self.fileNamesLabel)
                    .addComponent(self.filesPane)
                    .addComponent(self.clearFilesBtn)
                )
            )
        )
        layoutf.setVerticalGroup(
            layoutf.createParallelGroup()
            .addGroup(layoutf.createParallelGroup()
                .addGroup(layoutf.createSequentialGroup()
                    .addComponent(self.fileNamesLabel)
                    .addComponent(self.filesPane)
                    .addComponent(self.clearFilesBtn)
                )
            )
        )
        self.mapPanel = swing.JPanel()
        self.mapLabel = swing.JLabel("Mapped:")
        self.mapLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.mapLabel.setForeground(Color(255,102,52))
        self.mapPane = swing.JScrollPane()
        self.mapTxtArea = swing.JTextArea()
        self.mapTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.mapTxtArea.setLineWrap(True)
        self.mapPane.setViewportView(self.mapTxtArea)
        self.clearMapBtn = swing.JButton("Clear", actionPerformed=self.clearMAPLog)
        self.mapMapBtn = swing.JButton("Map", actionPerformed=self.mapMaps)
        layoutm = swing.GroupLayout(self.mapPanel)
        layoutm.setAutoCreateGaps(True)
        layoutm.setAutoCreateContainerGaps(True)
        self.mapPanel.setLayout(layoutm)
        layoutm.setHorizontalGroup(
            layoutm.createParallelGroup()
            .addGroup(layoutm.createSequentialGroup()
                .addGroup(layoutm.createParallelGroup()
                    .addComponent(self.mapLabel)
                    .addComponent(self.mapPane)
                    .addComponent(self.clearMapBtn)
                    .addComponent(self.mapMapBtn)                   
                )
            )
        )
        layoutm.setVerticalGroup(
            layoutm.createParallelGroup()
            .addGroup(layoutm.createParallelGroup()
                .addGroup(layoutm.createSequentialGroup()
                    .addComponent(self.mapLabel)
                    .addComponent(self.mapPane)
                    .addComponent(self.clearMapBtn)
                    .addComponent(self.mapMapBtn)
                )
            )
        )
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
          self.outputTxtArea.setText("BurpJS LinkFinder (Community Edition) loaded." + "\n" + "Copyright (c) 2022 Frans Hendrik Botes" + "\n" )
          # Also clear the set of processed URLs
          self.processed_urls.clear()
          
    def clearFilseLog(self, event):
          self.filesTxtArea.setText("")
          
    def clearMAPLog(self, event):
          self.mapTxtArea.setText("")      
          
    def exportLog(self, event):
        chooseFile = swing.JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        if ret == swing.JFileChooser.APPROVE_OPTION:
            filename = chooseFile.getSelectedFile().getCanonicalPath()
            self.callbacks.printOutput("\n" + "Export to : " + filename)
            try:
                with open(filename, 'w') as f:
                    f.write(self.outputTxtArea.text)
            except IOError as e:
                self.callbacks.printError("Error writing to file: " + str(e))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            url = messageInfo.getUrl()
            url_str = str(url)

            # <<< --- FIX: Check if URL has already been processed --- >>>
            if url_str in self.processed_urls:
                return
            
            # Check if the URL is in scope
            if not self.callbacks.isInScope(url):
                return
            
            response = messageInfo.getResponse()
            if response:
                # Check MIME type
                responseInfo = self.helpers.analyzeResponse(response)
                mime_type = responseInfo.getStatedMimeType()
                
                if mime_type and ('javascript' in mime_type.lower() or 'json' in mime_type.lower()) or '.js' in url_str or '.json' in url_str:
                    
                    # <<< --- FIX: Add to processed set before analysis --- >>>
                    self.processed_urls.add(url_str)
                    
                    try:
                        # Exclude casual JS files
                        if any(x in url_str for x in JSExclusionList):
                            self.callbacks.printOutput("\n" + "[-] URL excluded " + url_str)
                        else:
                            self.outputTxtArea.append("\n" + "[+] Valid URL found: " + url_str)
                            linkA = linkAnalyse(messageInfo, self.callbacks, self.helpers)
                            issueText = linkA.analyseURL()
                            
                            for counter, issue in enumerate(issueText):
                                self.outputTxtArea.append("\n" + "\t" + issue['link'])
                                
                                fullURL = issue['link']
                                if not linkA.valcheckFullURL(issue['link']):
                                    fullURL = urlparse.urljoin(url_str, issue['link'])
                                
                                if linkA.valcheckMappedList(fullURL, self.mapTxtArea):
                                    self.mapTxtArea.append("\n" + fullURL)
                                
                                filNam = path.basename(issue['link'].split('?')[0])
                                if linkA.isNotBlank(filNam) and linkA.checkValidFile(filNam) and (filNam not in self.filesTxtArea.text):
                                    self.filesTxtArea.append("\n" + filNam)

                    except UnicodeEncodeError:
                        self.callbacks.printOutput("Error in URL decode.")
                    except Exception as e:
                        self.callbacks.printError("Error in processHttpMessage: " + str(e))

    def extensionUnloaded(self):
        self.callbacks.printOutput("BurpJS LinkFinder v2 unloaded")
        return

    def mapMaps(self,event):
        self.q = queue.Queue()
        get_all_urls = self.mapTxtArea.getText()
        urls_list = list(set(get_all_urls.split('\n')))

        for url in urls_list:
            url = url.strip()
            if url:
                self.q.put(url)

        for j in range(10):
            t = threading.Thread(target=self.ProcessQueue)
            self.threads.append(t)
            t.start()

    def ProcessQueue(self):
        while not self.q.empty():
            each_url = self.q.get()
            self.ProcessURL(each_url)
            self.q.task_done()
        
    def URL_SPLITTER(self,url):
        URL_SPLIT = str(url).split("://",1)
        URL_PROTOCAL = URL_SPLIT[0]
        URL_PORT = 443 if URL_PROTOCAL == 'https' else 80
        URL_HOSTNAME_PATH = URL_SPLIT[1]
        URL_HOSTNAME = URL_HOSTNAME_PATH.split('/')[0].split('?')[0]
        if ':' in URL_HOSTNAME:
            URL_HOSTNAME, URL_PORT_STR = URL_HOSTNAME.split(':', 1)
            URL_PORT = int(URL_PORT_STR)
        URL_HOST_SERVICE = self.helpers.buildHttpService(URL_HOSTNAME, URL_PORT, URL_PROTOCAL == 'https')
        return URL_SPLIT, URL_PROTOCAL, URL_HOSTNAME, URL_PORT, URL_HOST_SERVICE

    def ProcessURL(self,url):
        if url.startswith('http://') or url.startswith('https://'):
            try:
                # Check if the discovered URL is in scope before sending a request
                if not self.callbacks.isInScope(URL(url)):
                    return
            
                URL_SPLIT,URL_PROTOCAL,URL_HOSTNAME,URL_PORT,URL_HOST_SERVICE = self.URL_SPLITTER(url)
                request = self.helpers.buildHttpRequest(URL(url))
                resp = self.callbacks.makeHttpRequest(URL_HOST_SERVICE, request)

                if resp and resp.getResponse():
                    self.callbacks.addToSiteMap(resp)
            except Exception as e:
                self.callbacks.printError("Error processing URL for site map: {} ({})".format(url, e))

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
        items = [{"link": m.group(1),"start":m.start(1),"end":m.end(1)} for m in re.finditer(regex, content)]
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

    def checkValidFile(self,fileNam):
        regexFile = r"^[a-zA-Z0-9](?:[a-zA-Z0-9 ._-]*[a-zA-Z0-9])?\.[a-zA-Z0-9_-][.].*"
        return fileNam and fileNam.strip() and bool(re.search(regexFile, fileNam))
       
    def isNotBlank(self,myString):
        return myString and myString.strip()

    def valcheckMappedList(self,myString,mapTxtArea):
        return myString not in mapTxtArea.text
    
    def valcheckFullURL(self,myString):
        return myString.lower().startswith(('http:', 'https:'))

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
