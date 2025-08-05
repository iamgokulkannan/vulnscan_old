import requests

def fetch_url(url):
    try:
        response = requests.get(url)
        return response.text
    except requests.exceptions.RequestException as e:
        return str(e)

if __name__ == "__main__":
    url = input("Enter the URL you want to fetch: ")
    content = fetch_url(url)
    print(content)
