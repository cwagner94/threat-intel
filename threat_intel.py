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
        response = requests.get(self.url, headers=headers)
        if response.status_code != 200:
            raise Exception(
                f'Request failed with status code {response.status_code}')
        self.api_response = response

    def get_ioc_data(self):
        self.ioc_data = self.api_response.json()


class Ioc:
    def __init__(self, search_term):
        self.ioc = search_term
        self.category = None

    def identify_ioc_category(self):
        self.is_filename()
        self.is_sha256()
        self.is_md5()
        self.is_ipv4()
        self.is_ipv6()
        self.is_domain()
        self.is_url()

    def is_filename(self):
        # TODO refine regex to say NOT .com, .net, .org, .edu, etc.
        filename_regex = r"\b[\w,\s-]+\.([a-zA-Z]{2}|[a-zA-Z]{3})\b"
        filename_match = re.search(filename_regex, self.ioc)
        if filename_match:
            self.category = 'files'

    def is_sha256(self):
        sha256_regex = r"\b[a-f0-9]{64}\b"
        sha256_match = re.search(sha256_regex, self.ioc)
        if sha256_match:
            self.category = 'files'

    def is_md5(self):
        md5_regex = r"\b[a-f0-9]{32}\b"
        md5_match = re.search(md5_regex, self.ioc)
        if md5_match:
            self.category = 'files'

    def is_ipv4(self):
        ipv4_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ipv4_match = re.search(ipv4_regex, self.ioc)
        if ipv4_match:
            self.category = 'ip_addresses'

    def is_ipv6(self):
        ipv6_regex = r"\b(?:[a-f0-9]{1,4}:){1,7}[a-f0-9]{1,4}|\b::(?:[a-f0-9]{1,4}:){0,6}[a-f0-9]{1,4}\b"
        ipv6_match = re.search(ipv6_regex, self.ioc)
        if ipv6_match:
            self.category = 'ip_addresses'

    def is_domain(self):
        domain_regex = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        domain_match = re.search(domain_regex, self.ioc)
        if domain_match:
            self.category = 'domains'

    def is_url(self):
        url_regex = r"\bhttps?:\/\/(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?\b"
        url_match = re.search(url_regex, self.ioc)
        if url_match:
            self.category = 'urls'


def main():
    user_input = UserInput()
    user_input.get_user_input()
    user_input.validate()
    if user_input.valid:
        ioc = Ioc(user_input.user_input)
        ioc.identify_ioc_category()
        vt = VirusTotal(ioc.ioc, ioc.category)
        vt.get_api_response()
        vt.get_ioc_data()
        pprint(vt.ioc_data)


if __name__ == "__main__":
    main()


# TODO Add requirements.txt
# TODO Break up test_threat_intel.py into multiple files in tests folder
# TODO How to differentiate between domains and filenames?
    # Look for common domain suffix (.com, .edu, .org, etc.)
    # Prompt user to specify
    # Is this a filename?
    # yes - proceed with filenames
    # no - proceed with domains
# Program breaks if ioc matches on more than one category
    # ex. both url and filename
    # If conflict arises, ask user to specify
    # Search for both, come back with the one that doesn't have an error
    # What if they're both valid?
