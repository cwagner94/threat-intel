import requests
from pprint import pprint
import os

VT_API_KEY = os.getenv('VT_API_KEY')

def main():
    # search_term = get_user_input()
    search_term = "e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5"
    pprint(check_virus_total_files(search_term))


def get_user_input():
    return input("Enter a Search Term: ")


def check_virus_total_files(id):
    url = f"https://www.virustotal.com/api/v3/files/{id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.text



if __name__ == "__main__":
    main()

