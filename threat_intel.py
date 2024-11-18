import requests
from pprint import pprint
import os
import re

VT_API_KEY = os.getenv('VT_API_KEY')


class UserInput:
    def __init__(self):
        self.user_input = ''
        self.valid = False

    def get_user_input(self):
        self.user_input = input("Enter a Search Term: ")

    def validate(self):
        if self.user_input:
            self.valid = True
        else:
            print('Invalid input. Please enter a search term')
            self.valid = False


class VirusTotal:
    def __init__(self, ioc, category):
        self.api_key = VT_API_KEY
        self.ioc = ioc
        self.category = category
        self.url = f"https://www.virustotal.com/api/v3/{category}/{ioc}"
        self.api_response = ''
        self.ioc_data = ''

    def get_api_response(self):
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        try:
            response = requests.get(self.url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            if response.status_code == 404:
                self.api_response = 'No data available. 404 error'
        except Exception as err:
            print(f'An error occurred: {err}')
            self.api_response = 'API error'
        else:
            self.api_response = response

    def get_ioc_data(self):
        if type(self.api_response) != str:
            self.ioc_data = self.api_response.json()
        else:
            self.ioc_data = self.api_response


class Ioc:
    def __init__(self, search_term):
        self.ioc = search_term
        self.ioc_type = ''
        self.category = ''

    def identify_ioc_category(self):
        self.is_sha256()
        self.is_md5()
        self.is_ipv4()
        self.is_ipv6()
        self.is_domain()
        self.is_url()
        self.set_category()

    def is_sha256(self):
        sha256_regex = r"\b[a-f0-9]{64}\b"
        sha256_match = re.search(sha256_regex, self.ioc)
        if sha256_match:
            self.ioc_type = 'sha256'

    def is_md5(self):
        md5_regex = r"\b[a-f0-9]{32}\b"
        md5_match = re.search(md5_regex, self.ioc)
        if md5_match:
            self.ioc_type = 'md5'

    def is_ipv4(self):
        ipv4_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ipv4_match = re.search(ipv4_regex, self.ioc)
        if ipv4_match:
            self.ioc_type = 'ipv4'

    def is_ipv6(self):
        ipv6_regex = r"\b(?:[a-f0-9]{1,4}:){1,7}[a-f0-9]{1,4}|\b::(?:[a-f0-9]{1,4}:){0,6}[a-f0-9]{1,4}\b"
        ipv6_match = re.search(ipv6_regex, self.ioc)
        if ipv6_match:
            self.ioc_type = 'ipv6'

    def is_domain(self):
        domain_regex = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        domain_match = re.search(domain_regex, self.ioc)
        if domain_match:
            self.ioc_type = 'domain'

    def is_url(self):
        url_regex = r"\bhttps?:\/\/(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?\b"
        url_match = re.search(url_regex, self.ioc)
        if url_match:
            self.ioc_type = 'url'

    def set_category(self):
        for ioc_type in self.ioc_type:
            if ioc_type == 'sha256' or ioc_type == 'md5':
                self.category = 'files'
            elif ioc_type == 'ipv4' or ioc_type == 'ipv6':
                self.category = 'ip_addresses'
            elif ioc_type == 'domain':
                self.category = 'domains'
            elif ioc_type == 'url':
                self.category = 'urls'


def main():
    print(VT_API_KEY)
    # user_input = UserInput()
    # user_input.get_user_input()
    # user_input.validate()
    # if user_input.valid:
    #     ioc = Ioc(user_input.user_input)
    #     ioc.identify_ioc_category()
    #     print(ioc.category)
    #     temp = []
    #     for category in ioc.category:
    #         vt = VirusTotal(ioc.ioc, category)
    #         vt.get_api_response()
    #         vt.get_ioc_data()
    #         temp.append(vt.ioc_data)
    #         # pprint(vt.ioc_data)
    # pprint(temp)


if __name__ == "__main__":
    main()

# VT docs: https://docs.virustotal.com/reference/file
# TODO Break up test_threat_intel.py into multiple files in tests folder
    # Separate integration tests from unit tests
# Modify logic between url and domain
    # If www. then domain
    # If http(s) then url