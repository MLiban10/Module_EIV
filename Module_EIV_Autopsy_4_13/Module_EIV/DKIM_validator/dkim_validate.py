import mailparser
from email.parser import BytesParser
#from dkim import verify as dkimVerify
import logging, time
import io, os

class dkimValidator:
    """Validates dkim in files from their given full path"""
    def __init__(self, files_path, output):
        self.files_path = files_path
        self.output = output        
    
    def getOutput(self):
        return self.output

    def Validator(self):
        logger = logging.getLogger()

        f = open(self.output + "/output.json", "w")
        analysis = '{"data":['

        # Repeat for every single eml file
        for filepath in files_path:
            t = time.localtime()

            errorMessage = io.StringIO()
            ch = logging.StreamHandler(errorMessage)
            logger.addHandler(ch)
            mail = BytesParser().parse(open(filepath, 'rb'))

            analysis += '{"filename":"'+filepath
            analysis += '","time":"'+ time.asctime(t)

            if dkim.verify( mail.as_bytes (), logger):
                analysis +='","status":"VALID"'
                analysis +=',"motive":""},\n'
            else :
                analysis +='","status":"INVALID"'
                analysis +=',"motive":"' + errorMessage.getvalue().split("(", 1)[0] + '"},\n'
        #alteração para o parse do json nao dar erro(tava com problema por causa dos \n)
        analysis = analysis[:-2]
        analysis += ']}'
        f.write(analysis)
        errorMessage.close()

        f.close()
        
if __name__=="__main__":
    try:
        import dkim
        # Receive and Parse arguments 
        from argparse import ArgumentParser
        parser = ArgumentParser()
        parser.add_argument('-fp', '--files_path',type=str)
        parser.add_argument('-o', '--output',type=str)
        args = parser.parse_args()
        files_path = args.files_path.replace("\\","/").split("#")
        output= args.output
        dkim_instance=dkimValidator(files_path,output)
        #error_output=dkim_instance.getOutput()
        dkim_instance.Validator()
        
    except Exception as e:
        #setup error logging
        error_output=os.getenv('APPDATA').replace("\\","/")+"/.autopsy/dev/python_modules/Module_EIV/DKIM_validator/logs"
        f = open(error_output+"/error.log", "w+")
        f.write(str(e))
        f.close()

#CODIGO DO JOAO ;BACKUP
"""
import mailparser
from email.parser import BytesParser
import dkim, logging, time
import io

logger = logging.getLogger()


#Repeat for every single eml file
for x in range(3):
    filename = "bet365.eml"#"Teste.eml"
    t = time.localtime()

    errorMessage = io.StringIO()
    ch = logging.StreamHandler(errorMessage)
    logger.addHandler(ch)
    mail = BytesParser().parse(open('../Emails/'+filename, 'rb'))

    analysis = "Filename: "+filename
    analysis += "\nAnalysis date:"+ time.asctime(t)

    if dkim.verify( mail.as_bytes (), logger):
        analysis +="\nStatus: VALID"
    else :
        analysis +="\nStatus: INVALID"
        analysis +="\nMotive:" + errorMessage.getvalue();
    print(analysis)
errorMessage.close()
"""
