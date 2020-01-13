# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.


# Sample report module for Autopsy.  Use as a starting point for new modules.
#
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/4.13.0/index.html for documentation

import os
import shutil
from io import StringIO, TextIOWrapper 
from java.lang import System
from java.util.logging import Level
from java.lang import Runtime
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus

from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import ModuleDataEvent

from javax.swing import JPanel
from javax.swing import JComboBox
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JTextArea
from java.awt import FlowLayout
from java.awt import BorderLayout 
from javax.swing import JFrame
from javax.swing import JButton

from org.sleuthkit.autopsy.ingest import IngestServices

#from email.parser import Parser
#import mailparser
#import dkim
#import sys
#sys.path.append("D:\\ESCOLA\\MCIF\\PS1\\DKIMValidator\\Modulo\\DKIM_validator")
#import dkim_validate
from org.sleuthkit.autopsy.coreutils import PlatformUtil
import json,csv
# TODO: Rename the class to something more specific
class SampleGeneralReportModule(GeneralReportModuleAdapter):

    # TODO: Rename this.  Will be shown to users when making a report
    moduleName = "Email Integrity Validator"
    lista=[]
    _logger = None
    def log(self, level, msg):
        if _logger == None:
            _logger = Logger.getLogger(self.moduleName)

        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    # TODO: Give it a useful description
    def getDescription(self):
        return "A Email Integrity Validator report module"

    # TODO: Update this to reflect where the report file will be written to
    def getRelativeFilePath(self):
        return "ValidatorResult.txt"

    def getDNSJTextFieldContent(self):
        return self.DNSJTextField.getText()

    def getLista(self):
        return self.lista

    # TODO: Update this method to make a report
    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.13.0/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):

        # For an example, we write a file with the number of files created in the past 2 weeks
        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.setMaximumProgress(2)

        # Find epoch time of when 2 weeks ago was
        currentTime = System.currentTimeMillis() / 1000
        minTime = currentTime - (14 * 24 * 60 * 60) # (days * hours * minutes * seconds)

        # Query the database for files that meet our criteria
        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()

        # Fetch Modules Directory
        modules_directory = PlatformUtil().getUserPythonModulesPath().replace("\\", "/")

        # Fetchs case files metadata but not content
        files_headers = sleuthkitCase.findAllFilesWhere("name like '%.eml'")
        fileCount = len(files_headers)
        
        # Write to the report file.
        reportName = os.path.join(baseReportDir, self.getRelativeFilePath())
        report = open(reportName, 'w')

        # Variable with files paths
        files_paths = ''
        for _file in files_headers:
            files_paths=files_paths + '#' + _file.localAbsPath
            #report.write("File Absolute Path: "+str(_file.localAbsPath)+"\n")
        files_paths = files_paths[1:]

        # Parse the '\'
        files_paths=str(files_paths).replace("\\","/")
        #report.write("File Count: "+str(fileCount)+"\n")

        # Temp directory to write extracted files
        temp_ouput = (str(str(modules_directory + "/Module_EIV/DKIM_validator/server/templates").replace("\\","/")))
        #report.write(str(files_paths))
        #report.write(os.abspath())
        """try:
            
        except Exception as e:
        """
        with open(str(modules_directory)+"/Module_EIV/DKIM_validator/data/nameservers.csv", 'w') as myfile:
            wr = csv.writer(myfile, delimiter=',',quoting=csv.QUOTE_NONE)
            if len(self.lista)>0:
                lista=self.lista
                wr.writerow(lista)
            else:
                myfile.truncate(0)

        
        # Detected DKIM signatures to create artifacts in blackboard
        invalid_dkim_filenames=[]
        valid_dkim_filenames=[]
        result_dictionary=''
        # Run DKIM validator
        try:

            p = Runtime.getRuntime().exec(("python %s/Module_EIV/DKIM_validator/dkim_validate.py -fp %s -o %s") %('"'+modules_directory+'"','"'+files_paths+'"','"'+temp_ouput+'"'))
            #report.write("python "+modules_directory+"/Module_EIV/DKIM_validator/dkim_validate.py -fp "+files_paths+" -o "+temp_ouput+" \n")
        except Exception as e:
            p.write("ERROR: "+str(e))
        finally:
            p.waitFor()
            with open(temp_ouput+"/output.json","r") as f:
                result_dictionary= json.load(f)#json.dumps(result_dictionary)
                
                for file in result_dictionary['data']:
                    if file['status']=='INVALID':
                        invalid_dkim_filenames.append(str(file['filename'].split('/')[-1]))
                    #else:
                        #valid_dkim_filenames.append(str(file['filename'].split('/')[-1]))

            total_emails=len(files_headers)
            total_emails_verified=len(result_dictionary['data'])
            report.write("""Emails to verify:{total_emails}\nEmails verifed:{total_emails_verified}\n""".format(total_emails=total_emails,total_emails_verified=total_emails_verified))
            index_1=0
            for d in result_dictionary['data']:
                index_1=index_1+1               
                report.write("""\tEmail({index}):\n\t\tfilename:{filename}\n\t\tstatus:{status}\n\t\tmotive:{motive}\n\t\ttime:{time}\n\n""".format(index=str(index_1),filename=d['filename'],status=d['status'],time=d['time'],motive=d['motive']))


        # Increment since we are done with step #1
        progressBar.increment()
        report.close()

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(reportName, self.moduleName, "Results Report")

        progressBar.increment()

        # Copy pre-created html file to report
        shutil.copy(os.path.join(temp_ouput, 'index.html'), os.path.join(baseReportDir, 'index.html'))


        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        art_message=''
        for file in files_headers:
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            for name in invalid_dkim_filenames:
                if file.name==name:
                    art_message="Invalid Email"
                else:
                    art_message="Valid Email"
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, SampleGeneralReportModule.moduleName, art_message)
            art.addAttribute(att)
            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except:
                pass
                #self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(self.getName(), BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))


        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)


    def getConfigurationPanel(self):
        self.configPanel = DV_ConfigPanel()
        self.lista=self.configPanel.lista
        return self.configPanel

###   Config Panel   ###

class DV_ConfigPanel(JPanel):

    def addClick(self, e):
        if self.DNSJTextField!='':
            self.DNSJTextArea.append(self.DNSJTextField.getText() + "\n")
            self.lista.append(self.DNSJTextField.getText())
            

    def __init__(self):
        self.initComponents()

    def getSelectedAddressBookOrderIndex(self):
        return self.orderComboBox.getSelectedIndex()

    def getAttTypeList(self):
        return self.att_type_list

    def initComponents(self):
        self.setLayout(FlowLayout())

        self.orderLabel = JLabel("DNS Server: ")
        self.add(self.orderLabel)

        self.lista = []

        self.DNSJTextField = JTextField(10)
        self.add(self.DNSJTextField)

        AddJButton = JButton( "Add", actionPerformed=self.addClick)
        self.add(AddJButton)

        noteLabel = JLabel("NOTE: The module will use the DNS provider configure by default.")
        self.add(noteLabel)

        self.DNSJTextArea = JTextArea(10, 30)
        self.DNSJTextArea.setEnabled(False)
        self.add(self.DNSJTextArea)
