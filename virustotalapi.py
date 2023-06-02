import requests
import base64
from datetime import date

#loading the virustotal API
api = "https://www.virustotal.com/api/v3/urls/"

def get_virus_total_data(phish_detect_url):

    #encoding the URL in Base64 format
    url_id = base64.urlsafe_b64encode(phish_detect_url.encode()).decode().strip("=")
    url = api + url_id
    print("url", url)
    headers = {
        "accept": "application/json",

        #providing the API key
        "x-apikey": "6da45fde1f9d2d396f1572e545ee8b8dbcdf6020ab1622d3a986c6a77c75a1b2"
    }

    response = requests.get(url, headers=headers)

    #retrieving the relavant information from the json response
    response_data = response.json()

    #Storing the response in a dictionary
    temp_response = {}
    #print(response_data)
    print(response_data, "response")
    temp_response['detectionDate'] = date.today()
    temp_response['firstSubmission'] = response_data['data']['attributes']['first_submission_date']
    temp_response['lastSubmission'] = response_data['data']['attributes']['last_submission_date']  
    temp_response['last_analysis_results'] = response_data['data']['attributes']['last_analysis_results']
    temp_response['last_analysis_stats'] = response_data['data']['attributes']['last_analysis_stats']
    return temp_response