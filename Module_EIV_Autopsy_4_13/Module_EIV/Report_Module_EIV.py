
import os
from java.lang import Runtime

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import BoxLayout
from javax.swing import JTextField
from javax.swing import JTextArea
from javax.swing import JButton

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JComboBox
#from javax.swing import JRadioButton
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestModuleGlobalSettingsPanel
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream

from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from java.lang import IllegalArgumentException
import json,csv
from org.sleuthkit.autopsy.coreutils import PlatformUtil
# TODO: Rename this to something more specific
class EmailFileIngestModuleWithUIFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Email Integrity Validator"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "A Email Integrity Validator report module"

    def getModuleVersionNumber(self):
        return "1.0"

    # TODO: Update class name to one that you create below
    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    # TODO: Keep enabled only if you need ingest job-specific settings UI
    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    # Note that you must use GenericIngestModuleJobSettings instead of making a custom settings class.
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return EmailFileIngestModuleWithUISettingsPanel(self.settings)


    def isFileIngestModuleFactory(self):
        return True


    # TODO: Update class name to one that you create below
    def createFileIngestModule(self, ingestOptions):
        return EmailFileIngestModuleWithUI(self.settings)


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class EmailFileIngestModuleWithUI(FileIngestModule):

    _logger = Logger.getLogger(EmailFileIngestModuleWithUIFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Autopsy will pass in the settings from the UI panel
    def __init__(self, settings):
        self.local_settings = settings

    def startUp(self, context):    
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # TODO: Add your analysis code in here.
    def process(self, file):

        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        modules_directory = PlatformUtil().getUserPythonModulesPath().replace("\\", "/")
        files_headers = sleuthkitCase.findAllFilesWhere("name like '%.eml'")
        fileCount = len(files_headers)

        #EVAL() function-----change in future
        lista=eval(self.local_settings.getSetting("DNS_LIST"))

        files_paths = ''
        for _file in files_headers:
            files_paths=files_paths + '#' + _file.localAbsPath
            #report.write("File Absolute Path: "+str(_file.localAbsPath)+"\n")
        files_paths = files_paths[1:]
        files_paths=str(files_paths).replace("\\","/")
        temp_ouput = (str(str(modules_directory + "/Module_EIV/DKIM_validator/server/templates").replace("\\","/")))
        
        with open(str(modules_directory)+"/Module_EIV/DKIM_validator/data/nameservers.csv", 'w') as myfile:
            wr = csv.writer(myfile, delimiter=',',quoting=csv.QUOTE_NONE)
            if len(lista)>0:
                wr.writerow(lista)
            else:
                myfile.truncate(0)

        invalid_dkim_filenames=[]
        valid_dkim_filenames=[]
        result_dictionary=''

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
            with open(str(modules_directory)+"/Module_EIV/DKIM_validator/data/results.txt", 'w') as myfile:
                myfile.write("""Emails to verify:{total_emails}\nEmails verifed:{total_emails_verified}\n""".format(total_emails=total_emails,total_emails_verified=total_emails_verified))
                index_1=0
                for d in result_dictionary['data']:
                    index_1=index_1+1               
                    myfile.write("""\tEmail({index}):\n\t\tfilename:{filename}\n\t\tstatus:{status}\n\t\tmotive:{motive}\n\t\ttime:{time}\n\n""".format(index=str(index_1),filename=d['filename'],status=d['status'],time=d['time'],motive=d['motive']))

        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        art_message=''
        for file in files_headers:
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            for name in invalid_dkim_filenames:
                if file.name==name:
                    art_message="Invalid Email"
                else:
                    art_message="Valid Email"
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, EmailFileIngestModuleWithUIFactory.moduleName, art_message)
            art.addAttribute(att)
            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except:
                pass
                #self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmailFileIngestModuleWithUIFactory.moduleName, BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        pass


# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class EmailFileIngestModuleWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):

    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()
        self.lista=[]
    def onClick(self, e):
        if self.DNSJTextField!='':
            self.DNSJTextArea.append(self.DNSJTextField.getText() + "\n")
            self.lista.append(str(self.DNSJTextField.getText()))
            self.local_settings.setSetting('DNS_LIST', str(self.lista))

    # TODO: Update this for your UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.DNSJTextField = JTextField(20) 
        self.DNSJTextField.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.DNSJTextField, self.gbcPanel0 ) 
        self.panel0.add( self.DNSJTextField ) 

        self.AddJButton = JButton( "Add", actionPerformed=self.onClick)
        self.AddJButton.setEnabled(True)
        self.rbgPanel0.add( self.AddJButton ) 
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.AddJButton, self.gbcPanel0 ) 
        self.panel0.add( self.AddJButton ) 
        
        self.DNSJTextArea = JTextArea(10, 30)
        self.gbcPanel0.gridx = 2 
        self.DNSJTextArea.setEnabled(False)
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.DNSJTextArea, self.gbcPanel0 ) 
        self.panel0.add( self.DNSJTextArea )

        self.add(self.panel0)

    # TODO: Update this for your UI
    def customizeComponents(self):
        one=1
    # Return the settings used
    def getSettings(self):
        return self.local_settings