import pickle
import pandas as pd
import numpy as np 
import urllib
from urllib.request import urlopen
from urllib.parse import urlparse
from difflib import SequenceMatcher
import whois 
import datetime                                                               
import socket
import ipaddress
import re
import joblib
from urllib.parse import urlparse
from urllib.parse import urlencode
from bs4 import BeautifulSoup 
from flask import Flask, request
from flask_cors import CORS
from virustotalapi import get_virus_total_data
from newlocation import get_ip_details

# Load the pickled model
with open('classifier_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open("model.txt", "r") as file:
  file_content = file.read()
  valid_model =(file_content.split("\n"))

# 1.This function extracts the domain from the URL by parsing it using urlparse library and then returns the domain.
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2.This function checks if the given URL contains an IP address or not.
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip

# 3.This function checks if the given URL contains an '@' symbol, which is typically not present in a standard URL.
def haveAtSign(url):
  if "@" in url:
    at = 1    
  else:
    at = 0    
  return at

# 4.This function takes a URL and returns a binary value indicating whether its length is greater than or equal to 54 or not.
def getLength(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1            
  return length

# 5.This function takes a URL as input and returns the depth of its path.
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 6.This function checks if there is redirection in the given URL.
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# 7.This function extracts the domain from a given URL using the urlparse method.
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0
  
#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. This function checks if the given URL has been shortened using a URL shortening service by checking for the presence of the domain name of known URL shortening services in the URL.
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0
    
# 9.This function checks whether the domain name in the given URL contains a hyphen or not.
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1           
    else:
        return 0            

# 10.This function takes a URL and extracts the domain name from it. 
def ippresent(url):
    domain = urlparse(url).netloc
    try:
        ip = socket.gethostbyname("domain")
        return 1
    except:
        return 0
    
# 11.This function checks if the input URL uses HTTPS protocol or not.
def https_token(url):
    if re.findall(r"^https://", url):
        return 0
    else:
        return 1
    
# 12.The function get_protocol_count takes a URL as input and returns the number of times the protocol (either "http" or "https") appears in the URL.
def get_protocol_count(url):
    http_count = url.count('http')
    https_count = url.count('https')
    http_count = http_count - https_count #correcting the miscount of https as http
    return (http_count + https_count)

# 13.The function get_protocol takes a URL as input and returns a binary value indicating the protocol used in the URL.
def get_protocol(url):
    protocol = urlparse(url)
    if(protocol.scheme == 'http'):
        return 1
    else:
        return 0
    
# 14.The function get_special_char_count takes a URL as input and returns the number of special characters in the URL.
def get_special_char_count(url):
    count = 0
    special_characters = [';','+=','_','?','=','&','[',']']
    for each_letter in url:
        if each_letter in special_characters:
            count = count + 1
    return count

# 15.The function dns_record takes a URL as input and returns a binary value indicating whether the domain has a DNS record or not.
def dns_record(url):
    domain_name = urlparse(url).netloc
    try:    
        rec = whois.whois(domain_name)
        return 1
    except:
        return 0    
    
# 16.This function takes in a URL as an input and returns the Alexa global rank of the website.   
def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank= int(rank)
        return rank
    except:
        return 0 
     
# 17.The function domainAge takes a URL as input and returns the age of the domain in days.
def domainAge(url):
    try:
        domain_name = urlparse(url).netloc
    
        whois_response = whois.whois(domain_name)
        creation_date = whois_response.creation_date
        creation_date = creation_date[0].date()
        today = datetime.date.today()
        days = (today - creation_date).days
        if (days/30 < 6):
            return 1
        return 0
    except:
        return 0
    
# Define a function to extract features from a URL
def extract_features(url):
    parsed_url = urlparse(url)
    feature = []
    feature.append(havingIP(url))
    feature.append(haveAtSign(url))
    feature.append(getLength(url))
    feature.append(getDepth(url))
    feature.append(redirection(url))
    feature.append(httpDomain(url))
    feature.append(tinyURL(url))
    feature.append(prefixSuffix(url))  
    feature.append(ippresent(url))
    feature.append(https_token(url))
    feature.append(get_protocol_count(url))
    feature.append(get_protocol(url))
    feature.append(get_special_char_count(url))

    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    feature.append(dns_record(url))
    feature.append(web_traffic(url))
    feature.append(domainAge(url))

    return feature


def detect_phish(url):
  result = {}
  result['domain'] = getDomain(url) #fetchs domain

  if (url):
    print(url.split('/')[2])
    result['location_details'] = get_ip_details(url) #fetchs location details
    result["ip-address"] = socket.gethostbyname(url.split('/')[2]) #fetchs IP address
    result['virus-total-data'] = get_virus_total_data(url) #fetchs data from virustotal API

    feature_vector = [havingIP(url), haveAtSign(url), getLength(url), getDepth(url), redirection(url), httpDomain(url), tinyURL(url), prefixSuffix(url), ippresent(url), 
                  https_token(url), get_protocol_count(url), get_protocol(url), get_special_char_count(url), dns_record(url), web_traffic(url),  domainAge(url)]

    prediction = model.predict([feature_vector])[0]

    result["source_url"] = url
    for data in valid_model:
      if data in url or data[:-1] in url:
        result['predication'] = 'Legitimate'
        return result
      
    if prediction == 0:
      result['predication'] = 'Legitimate'
      #result['predication'] = 'Phishing'
      return result
    else:
      result['predication'] = 'Phishing'
      #result['predication'] = 'Legitimate'
      return result
  
  return {"predication": "Failed: Url is not defined."}


# create a Flask application instance
app = Flask(__name__)

# enable Cross-Origin Resource Sharing (CORS) for the app
CORS(app)

# define a route for the '/search' endpoint and specify that it accepts only GET requests
@app.route('/search', methods=['GET'])
def search_url():

  # call the detect_phish function with the URL passed as a query argument and return the result
  return detect_phish(request.args.get("url"))

# start the Flask application server
if __name__ == '__main__':
    
    # make the server available from any IP address and use port 9696
    app.run(host='0.0.0.0', port=9696)