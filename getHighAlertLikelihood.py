import json
import requests 
import pandas as pd
from bs4 import BeautifulSoup, Tag
import os

urllist = []
tagNumbers = []
data = []
tagslikelihood = []
tag_numbers = []
base_url = "https://cwe.mitre.org/data/definitions/{}.html"

results = []

def load_existing_data(file_path):
    """Load existing data from an Excel file, if it exists, otherwise return an empty DataFrame."""
    if os.path.exists(file_path):
        return pd.read_excel(file_path)
    else:
        return pd.DataFrame()
    
# Function to parse HTML and extract the value of "Likelihood_Of_Exploit"
def extract_likelihood_of_exploit(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    element = soup.find(id='Likelihood_Of_Exploit')
    if element:
        return element.get_text(strip=True)
    return None

def append_data_to_excel(new_data, file_path):
    """Append new data to an existing Excel file or create a new file if it doesn't exist."""
    # Load existing data
    existing_data = load_existing_data(file_path)
    
    # Convert new data to a DataFrame
    new_data_df = pd.DataFrame(new_data)
    
    # Append new data to existing data
    updated_data = pd.concat([existing_data, new_data_df], ignore_index=True)
    
    # Save the updated data back to the Excel file
    updated_data.to_excel(file_path, index=False)

    
# Function to get HTML content from a URL
def get_html(url):
    response = requests.get(url)
    response.raise_for_status()  # Ensure we notice bad responses
    return response.text

def custom_serializer(obj):
    if isinstance(obj, Tag):
        return obj.text.strip()
    # Add more custom serialization logic if needed
    raise TypeError(f"Type {type(obj)} not serializable")
def substring_between_strings(text, start, end):
    start_idx = text.find(start)
    end_idx = text.find(end)
    if start_idx != -1 and end_idx != -1:
        return text[start_idx + len(start):end_idx]
    else:
        return ""
# Function to parse HTML content and extract relevant information
def parse_html(html_content,tagNumber,tag):
    soup = BeautifulSoup(html_content, 'html.parser')

    
    # Extract LikelihoodOfExploit
    LikelihoodOfExplotURL = 'oc_'+tagNumber+'_Likelihood_Of_Exploit'
 
    LikelihoodOfExploit = soup.find(attrs={'id': LikelihoodOfExplotURL})
    #LikelihoodOfExploit = substring_between_strings(LikelihoodOfExploit, 'indent">', '</div></div></div>')

    print(LikelihoodOfExploit)
    
    # Extract other relevant information
  
    #tagslikelihood.append(LikelihoodOfExploit)
    data.append(tag)
    data.append(LikelihoodOfExploit)
  

print("Get data")
#url = 'https://github.com/nikki786/Netskope_bandit/code-scanning/alerts'
url = 'https://api.github.com/repos/nikki786/Netskope_bandit/code-scanning/alerts?severity=high'
headers = {'user-agent': 'my-app/0.0.1', 'Accept': 'application/vnd.github+json','Authorization': 'Bearer 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', 'X-GitHub-Api-Version': '2022-11-28' }


response = requests.get(url, headers=headers, timeout=10)

#print(response.content)
parsedjson = json.loads(response.content)
length = len(parsedjson[0])
#print(length)

for i in range(len(parsedjson[0])) :
   #print(parsedjson[i]['number'])
   Tagslist = {}
   issuenumber = parsedjson[i]['number'] 
   data.append(parsedjson[i]['number'])
   Tagslist = (parsedjson[i]['rule']['tags'])
   
   # Remove 'security' from the list
   filtered_list = [item for item in Tagslist if item not in ['security', 'correctness']]

# Extract numbers and create a new list
   numbers_list = [item.split('-')[-1] for item in filtered_list]

# Print the results
   #print("Filtered List:", filtered_list)
   #print("Numbers List:", numbers_list)
   #print(issuenumber,'-',Tagslist)

   for tag_number in numbers_list:
      url = base_url.format(tag_number.lstrip('0'))
      try:
          html_content = get_html(url)
          likelihood_of_exploit = extract_likelihood_of_exploit(html_content)
          likelihood_of_exploit = likelihood_of_exploit.replace('Likelihood Of Exploit','',-1)
          if ("Medium" not in likelihood_of_exploit) and ("Low" not in likelihood_of_exploit) and ("Info" not in likelihood_of_exploit):
           print('Alert Number -',issuenumber ,',', 'CWE-',tag_number, ',', 'likelihood_of_exploit -', likelihood_of_exploit)

          results.append({
              "Tag Number": tag_number,
              "Likelihood_Of_Exploit": likelihood_of_exploit
          })
      except Exception as e:
          #print(f"Error processing {tag_number}: {e}")
          results.append({
              "Tag Number": tag_number,
              "Likelihood_Of_Exploit": None
          })

# Create a DataFrame and save to Excel
df = pd.DataFrame(results)
df.to_excel("Likelihood_Of_Exploit.xlsx", index=False)

print("Data has been written to Likelihood_Of_Exploit.xlsx")
