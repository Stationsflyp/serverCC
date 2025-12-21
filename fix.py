import os  
filepath = r\"c:\Users\delea\Desktop\OxcyShop - Auth Corp\OxcyShop_AuthWebsite\components\dashboard\tabs\users-tab.tsx\"  
  
with open(filepath, \"r\") as f:  
    content = f.read()  
  
new_content = content.replace(\"      )}\n    </>\", \"      )}\n    </div>\n    </>\")  
  
with open(filepath, \"w\") as f:  
    f.write(new_content)  
print(\"Done\")  
