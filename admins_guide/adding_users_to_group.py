'''
**DISCLAIMER:**
    Please note that this code is for educational purposes only.
    It is not intended to be run directly in production.
    This is provided on a best effort basis.
    Please make sure the code you run does what you expect it to do.
'''

import argparse
import requests

print(
    '**DISCLAIMER:** Please note that this code is for educational purposes only. '
    'It is not intended to be run directly in production. This is provided on a best effort basis. '
    'Please make sure the code you run does what you expect it to do.\n'
)

def add_users_to_group(apikey, group_id, email_addresses):
    '''
    Adding users (by their email addresses) to Google Threat Intelligence group.
    Google Threat Intelligence API endpoint reference: https://gtidocs.virustotal.com/reference/update-group-users
    '''
    print(email_addresses)
    url = f'https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users'
    headers = {
        'accept': 'application/json',
        'x-apikey': apikey,
        'content-type': 'application/json',
    }
    payload = {'data': [{'type': 'user', 'id': e} for e in email_addresses]}
    res = requests.post(url, json=payload, headers=headers)
    res.raise_for_status()
    print('Users added successfully to the group.\n')

def main():
    parser = argparse.ArgumentParser(
        description='Adding new members to your Google Threat Intelligence group by their email addresses.'
    )
    parser.add_argument('--apikey', required=True, help='Your Google Threat Intelligence API key')
    parser.add_argument(
        '--group_id',
        required=True,
        help='Your Google Threat Intelligence group ID. Check https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/GTI_group_admins_API_guide.md Requirements.',
    )
    parser.add_argument(
        '--email_addresses',
        required=True,
        default=[],
        nargs='+',
        help='List of email addresses of users you want to make members of your group',
    )
    args = parser.parse_args()

    if args.email_addresses:
        add_users_to_group(args.apikey, args.group_id, args.email_addresses)

if __name__ == '__main__':
    main()
