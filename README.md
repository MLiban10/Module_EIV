# Email Integrity Validator
Information:
 This Autopsy module was developed and teste using python3 and autopsy 4.12
 
## Setup:
 1. Have python3 installed
 2. Have Autopsy v4.12 installed
 3. Access "Module_EIV" folder and run "python -m pip install -r req_packages.txt --user"
 4. Copy Module_EIV folder to autopsy python modules folder
 
## Run:
 1. Open autopsy and generate the "Email Intergrity Validator" report
 2. Run the command "python server.py" inside "Module_EIV/DKIM_validator/server" folder
 3. Access the information through 127.0.0.1:8080
