import json
import urllib.parse
import requests
from datetime import datetime, timedelta
import logging
from requests.api import get


class OfficeIncidentAlerts():

    '''Define the logging method; get the IDs from the customer specific (classified) file; define the token url, the subscriptions, API url and the request body.'''
    def __init__(self, tenantId, clientId, clientSecret, customerName):
        logging.basicConfig(filename='/etc/encrypted/mount/siem/office365/status.log', format='%(asctime)s - %(levelname)s - %(message)s',
                    level=logging.DEBUG)

        self.tenantId = tenantId
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.customerName = customerName

        self.token_url = "https://login.windows.net/{}/oauth2/token".format(self.tenantId) 
        self.subscriptions = ['Audit.Exchange', 'Audit.SharePoint', 'DLP.All', 'Audit.General', 'Audit.AzureActiveDirectory']
        self.url = 'https://manage.office.com'

        self.body = {
                'resource': self.url,
                'client_id': self.clientId,
                'client_secret': self.clientSecret,
                'grant_type': 'client_credentials'
            }


    '''Get the access token that is needed for making the request to the API'''
    def get_access_token(self):
        data = urllib.parse.urlencode(self.body).encode("utf-8")
        response = requests.get(self.token_url, data=data)
        if response.status_code == 200:
            logging.info('Token request returned 200')
            token = json.loads(response.text)["access_token"]
            logging.info('Token: {}'.format(token))
            return token

        logging.error(
            "Failed to request access token. Request returned {0}: {1}".format(response.status_code, response.reason))


    '''Manage the different subscriptions that define which audit logs the script will retrieve form the API'''
    def manage_subscriptions(self, subscriptions, clientId, token):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer {}'.format(token)
        }

        for subscription in subscriptions:
            url = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/start?contentType={}'.format(clientId, subscription)
            response = requests.post(url, headers=headers)
            if response.status_code == 200:
                logging.info("{} subscription was succesfully started.".format(subscription))
            elif response.status_code == 400:
                logging.info("Request to start {} returned message: {}.".format(subscription, json.loads(response.text)["error"]["message"]))
            else:
                logging.error("Request {} failed with {} - {}".format(url, response.status_code, response.text))


    '''Retrieve the events form the predefined subscriptions using the authentication token form before'''
    def retrieve_alerts(self, token, clientId, subscription, minutes):
        now = datetime.now().replace(microsecond=0)
        start_time = str(now - timedelta(hours=3)).replace(' ', 'T')
        end_time = str(now).replace(' ', 'T')

        url = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/content?contentType={}&startTime={}&endTime={}'.format(clientId, subscription, start_time, end_time)

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer {}'.format(token)
        }

        content = requests.get(url, headers=headers)

        if content.status_code == 200:
            logging.info('Alert request returned 200')
            for blob in json.loads(content.text):
                response = requests.get(blob["contentUri"], headers=headers)
                if response.status_code == 200:
                    events = response.text
                    return json.loads(events)
                else:
                    logging.error("Request {} failed with {} - {}".format(blob["contentUri"], response.status_code, response.text))
        else:
            logging.error("Request {} failed with {} - {}".format(url, content.status_code, content.text))


    '''If the alert contains nested JSON, then this function is used to flatten it so that it is easier processed in DIs SIEM alert dashboard'''
    def flatten_data(self, alert):
        out = {}

        def flatten(_object, fieldName=''):
            try:
                if type(_object) is dict:
                    keys = list(_object.keys())
                    key_synonyms = ['Name', 'Key', 'Value']
                    if len(_object) == 2 and any(key in key_synonyms for key in keys):
                        flatten(_object[keys[1]], fieldName + '.' + _object[keys[0]])
                    else:
                        for key in _object:
                            flatten(_object[key], fieldName + key)
                elif type(_object) is list:
                    for _dict in _object:
                        flatten(_dict, fieldName)
                else:
                    out[fieldName] = _object
            except Exception as e:
                logging.error("Exception {}. Failed to flatten alert {}!".format(e, alert))
        flatten(alert)
        return out


    '''This is the code that actually binds all the previous functions together and generates the alerts that are fed into the DI SIEM solution'''
    def get_alerts(self):
        try:
            token = self.get_access_token()
            self.manage_subscriptions(self.subscriptions, self.clientId, token)
            count_new = 0

            for subscription in self.subscriptions:
                alerts = self.retrieve_alerts(token, self.clientId, subscription, 30)

                if alerts:
                    for alert in alerts:
                        alert['customerName'] = self.customerName
                        alert = self.flatten_data(alert)
                        with open('/etc/encrypted/mount/siem/office365/alerts.json', "a") as file:
                            file.write(json.dumps(alert) + '\n')
                        count_new += 1
                else:
                    pass

            logging.info('{} new alerts were appended to office365.json'.format(count_new))

        except Exception as e:
            logging.error("Exception {}. Failed to retrieve and append alerts!".format(e))
