import socket
import requests
import json
import folium
import webbrowser
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def get_ip_details(url):

    # Initialize an empty dictionary for storing the results
    result = {}

    # Append a trailing slash to the URL to avoid errors in the IP address lookup
    url = url + "/"

    # Create a string for use in the screenshot filename
    url_for_screenshot = url.replace("https://", "")
    url_for_screenshot = url_for_screenshot.replace(".", "_")
    url_for_screenshot = url_for_screenshot.replace("/", ".png")

    # Extract the domain name from the URL
    domain_name = url.split('/')[2]

    # Lookup the IP address associated with the domain name
    ip_address = socket.gethostbyname(domain_name)

    # Call the APIIP service to get additional IP details
    access_key = '3b89c992-d5b9-4cd8-91ba-3d7ff961605f'
    apiip = f'http://apiip.net/api/check?ip={ip_address}&accessKey={access_key}'    

    response = requests.get(apiip)

    result = json.loads(response.text)

    # Add the screenshot URL to the results dictionary
    result['screenshot_url'] = url_for_screenshot

    # Use Selenium and ChromeDriver to capture a screenshot of the website
    options = Options()
    options.headless = True

    driver = webdriver.Chrome(options=options)
    driver.get(url)
    driver.save_screenshot("./phising-detection-frontend/public/"+url_for_screenshot)
    driver.quit()
    
    # Return the results dictionary
    return result