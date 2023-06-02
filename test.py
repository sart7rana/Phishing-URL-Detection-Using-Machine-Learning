# MAIN BACKEND CODE

import pickle
from urllib.parse import urlparse
#import allfeature
import pickle 
import pandas as pd 
import numpy as np 
import matplotlib.pyplot as plt
import urllib
from urllib.request import urlopen
from flask import Flask, request 
from flask.templating import render_template
from difflib import SequenceMatcher
import requests
import whois 
import datetime 
import time                                                                                  
import socket
import ipaddress
import re
from urllib.parse import urlparse
from urllib.parse import urlencode
from bs4 import BeautifulSoup

# Load the saved model from the file
with open('classifier_model.pkl', 'rb') as f:
    forest = pickle.load(f)

#url = 'https://www.google.com/search?q=python+machine+learning'
#url = 'https://www.google.com/search?q=python+machine+learning&sxsrf=APwXEdeEndsMaC-l_3S3JyY9oCVLPlwOUQ%3A1684895598363&ei=bndtZPvhFbiaseMPofG0iAg&ved=0ahUKEwj70P6c9Yz_AhU4TWwGHaE4DYEQ4dUDCA8&uact=5&oq=python+machine+learning&gs_lcp=Cgxnd3Mtd2l6LXNlcnAQAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQigUQsAMQQzIKCAAQigUQsAMQQzIKCAAQigUQsAMQQzIKCAAQigUQsAMQQzINCAAQ5AIQ1gQQsAMYATINCAAQ5AIQ1gQQsAMYATINCAAQ5AIQ1gQQsAMYATIPCC4QigUQyAMQsAMQQxgCMg8ILhCKBRDIAxCwAxBDGAIyEgguEIoFENQCEMgDELADEEMYAjIPCC4QigUQyAMQsAMQQxgCSgQIQRgAUABYAGCPCGgBcAF4AIABAIgBAJIBAJgBAMgBE8ABAdoBBggBEAEYCdoBBggCEAEYCA&sclient=gws-wiz-serp'
#url = 'https://www.google.com/search?q=python+machine+learning&sxsrf=APwXEdeEndsMaC-l_3S3JyY9oCVLPlwOUQ%3A1684895598363&ei=bndtZPvhFbiaseMPofG0iAg&ved=0ahUKEwj70P6c9Yz_AhU4TWwGHaE4DYEQ4dUDCA8&uact=5&oq=python+machine+learning&gs_lcp=Cgxnd3Mtd2l6LXNlcnAQAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQRxDWBBCwAzIKCAAQigUQsAMQQzIKCAAQigUQsAMQQzIKCAAQigUQsAMQQzIKCAAQigUQsAMQQzINCAAQ5AIQ1gQQsAMYATINCAAQ5AIQ1gQQsAMYATINCAAQ5AIQ1gQQsAMYATIPCC4QigUQyAMQsAMQQxgCMg8ILhCKBRDIAxCwAxBDGAIyEgguEIoFENQCEMgDELADEEMYAjIPCC4QigUQyAMQsAMQQxgCSgQIQRgAUABYAGCPCGgBcAF4AIABAIgBAJIBAJgBAMgBE8ABAdoBBggBEAEYCdoBBggCEAEYCA&sclient=gws-wiz-serp'

#url = 'http://www.sribaladayanidhi.org/wp-content/hl/2020dhl_topscript/dhl_topscript/source/index.php?email=jsmith@imaphost.com'
#url = 'http://groupwhatsapp-bokep.viewdns.net/'
#url = 'https://www.youtube.com'
url = 'https://tweedy-light.000webhostapp.com/home'

# 1.Domain of the URL (Domain) 
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip

# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1    
  else:
    at = 0    
  return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1            
  return length

# 5.Gives number of '/' in URL (URL_Depth) & #The function getDepth takes a URL as input and returns the depth of the URL.
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 6.Checking for redirection '//' in the url (Redirection) & #The function redirection takes a URL as input and returns a binary value indicating whether the URL is a redirection URL or not.
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain) 
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

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0
    
# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate
    
def ippresent(url):
    domain = urlparse(url).netloc
    try:
        ip = socket.gethostbyname("domain")
        return 1
    except:
        return 0
    
def https_token(url):
    if re.findall(r"^https://", url):
        return 0
    else:
        return 1
    
#The function get_protocol_count takes a URL as input and returns the number of times the protocol (either "http" or "https") appears in the URL.
def get_protocol_count(url):
    http_count = url.count('http')
    https_count = url.count('https')
    http_count = http_count - https_count #correcting the miscount of https as http
    return (http_count + https_count)

#The function get_protocol takes a URL as input and returns a binary value indicating the protocol used in the URL.
def get_protocol(url):
    protocol = urlparse(url)
    if(protocol.scheme == 'http'):
        return 1
    else:
        return 0
    
#The function get_special_char_count takes a URL as input and returns the number of special characters in the URL.
def get_special_char_count(url):
    count = 0
    special_characters = [';','+=','_','?','=','&','[',']']
    for each_letter in url:
        if each_letter in special_characters:
            count = count + 1
    return count

#The function dns_record takes a URL as input and returns a binary value indicating whether the domain has a DNS record or not.
def dns_record(url):
    domain_name = urlparse(url).netloc
    try:    
        rec = whois.whois(domain_name)
        return 1
    except:
        return 0    
    
def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank= int(rank)
        return rank
    except:
        return 0 #0 = Phishing
    
# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
#The function domainAge takes a URL as input and returns the age of the domain in days.
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
    
def feature_extraction(url,label):

  feature = []

  #Address bar based features (13)
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

  #Domain based features (3)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1

  feature.append(dns_record(url))
  feature.append(web_traffic(url))
  feature.append(domainAge(url))
  
  return feature

parsed_url = urlparse(url)

# Create a feature vector containing the extracted features
feature_vector = [havingIP(url), haveAtSign(url), getLength(url), getDepth(url), redirection(url), httpDomain(url), tinyURL(url), prefixSuffix(url), ippresent(url), 
                  https_token(url), get_protocol_count(url), get_protocol(url), get_special_char_count(url), dns_record(url), web_traffic(url),  domainAge(url)]

# Make a prediction using the loaded model
prediction = forest.predict([feature_vector])[0]

# Print the prediction
if prediction == 0:
    print('The URL ' + url + ' is classified as legitimate.')
else:
    print('The URL ' + url + ' is classified as a phishing attempt.')