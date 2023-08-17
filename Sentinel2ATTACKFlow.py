import json
from stringprep import c7_set
import sys 
import os
import glob

banner = '''
   _____ _______   _____________   __________   ___   ___  _______________     ________ __ ________    ____ _       __
  / ___// ____/ | / /_  __/  _/ | / / ____/ /  |__ \ /   |/_  __/_  __( _ )   / ____/ //_// ____/ /   / __ \ |     / /
  \__ \/ __/ /  |/ / / /  / //  |/ / __/ / /   __/ // /| | / /   / / / __ \/|/ /   / ,<  / /_  / /   / / / / | /| / / 
 ___/ / /___/ /|  / / / _/ // /|  / /___/ /___/ __// ___ |/ /   / / / /_/  </ /___/ /| |/ __/ / /___/ /_/ /| |/ |/ /  
/____/_____/_/ |_/ /_/ /___/_/ |_/_____/_____/____/_/  |_/_/   /_/  \____/\/\____/_/ |_/_/   /_____/\____/ |__/|__/   
                                                                                                                      
'''

print(banner)

SentinelCoverage = sys.argv[1] # Sentinel Coverage Navigation Layer (JSON)

with open(SentinelCoverage,"r") as f:
    SNTCoverage  = json.load(f)

Coverage = []
for technique in SNTCoverage["techniques"]:
    #print(technique["techniqueID"])
    Coverage.append(technique["techniqueID"])

Coverage = list(dict.fromkeys(Coverage)) # Remove Duplicates

ATTACKFlow_Files_Path = sys.argv[2]

if os.path.isfile(ATTACKFlow_Files_Path) == False:
  for Afb_File in glob.iglob(ATTACKFlow_Files_Path  + '**/**'):
    if Afb_File.endswith('.afb'):
        FileTitle = str(Afb_File).split("/")[1]
        with open(Afb_File,"r") as f:
            afb_data = json.load(f)
            ATTACK_Flow_Techniques = []
            for t in afb_data["objects"]:
                if t["template"] == "action":
                    ATTACK_Flow_Techniques.append(t["properties"][3][1])
            ATTACK_Flow_Techniques =  list(dict.fromkeys(ATTACK_Flow_Techniques)) # Remove Duplicates

            # Identify Covered TTPs

            CoveredTechniques = []
            for c in Coverage:
                    if str(c) in ATTACK_Flow_Techniques:
                        #print(c)
                        CoveredTechniques.append(c)


            # Add Sentinel Coverage Field

            for p in afb_data["schema"]["templates"]:
                if p["id"] == "action":
                    Property = p["properties"] 
                    Property["Sentinel_Coverage"] = {"type":2}

            for T in afb_data["objects"]:
                    if T["template"] == "action":
                        #print(T)
                        for c in CoveredTechniques:
                            if c in str(T["properties"]):
                                #print(c)
                                T["properties"].append(["Sentinel_Coverage", "COVERED"])

            # Generate the new afb file

            FileName = str(Afb_File).split("/")[1].replace(".afb","")
            with open(FileName+"-Updated.afb", "w") as write_file:
                json.dump(afb_data, write_file, indent=4)

     







