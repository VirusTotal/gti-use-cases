'''
**DISCLAIMER:**
    Please note that this code is for educational purposes only.
    It is not intended to be run directly in production.
    This is provided on a best effort basis.
    Please make sure the code you run does what you expect it to do.
'''

import argparse
from pprint import pprint
import requests
from datetime import date
from datetime import datetime

print(
    '**DISCLAIMER:** Please note that this code is for educational purposes only. '
    'It is not intended to be run directly in production. '
    'This is provided on a best effort basis. '
    'Please make sure the code you run does what you expect it to do.\n'
)

def days_from_date(start_date):
    '''
    Getting the number of days between a specified day and current date.
    '''
    today = date.today()
    start_date = datetime.strptime(start_date, '%Y%m%d').date()
    if today > start_date:   
        return (today-start_date).days

def get_group_users(apikey, group_id):
    '''
    Getting group users ID list (by group ID).
    Google Threat Intelligence API endpoint reference: https://gtidocs.virustotal.com/reference/get-group-users
    '''

    users = []
    url = f'https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users'
    headers = {'accept': 'application/json', 'x-apikey': apikey}

    while url:
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        res = res.json()
        users.extend([e['id'] for e in res['data']])
        url = res.get('links', {}).get('next', None)
    return users

def get_user_api_consumption(apikey, user_id, start_date, last_date):
    '''
    Getting Google Threat Intelligence API user consumption between 2 dates (by user ID). 
        Please note that available data includes only the last 30 natural days.
    Google Threat Intelligence API endpoint reference: https://gtidocs.virustotal.com/reference/user-api-usage
    '''

    url = f'https://www.virustotal.com/api/v3/users/{user_id}/api_usage?start_date={start_date}&end_date={last_date}'
    headers = {'accept': 'application/json', 'x-apikey': apikey}
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    res = res.json()
    # remove not consuming endpoints
    res['data'].pop('daily_endpoints_not_consuming_quota')
    # remove days with no consumption
    keys = list(res['data']['daily'].keys())
    for key in keys:
        if not res['data']['daily'].get(key):
            res['data']['daily'].pop(key)
    return res

def main():
    parser = argparse.ArgumentParser(
        description='Getting Google Threat Intelligence API user consumption between 2 dates.'
    )
    parser.add_argument('--apikey', required=True, help='Your Google Threat Intelligence API key')
    parser.add_argument(
        '--group_id',
        required=True,
        help='Your Google Threat Intelligence group ID. Check https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/GTI_group_admins_API_guide.md Requirements.',
    )
    parser.add_argument(
        '--start_date',
        required=True,
        help='Start day (yyyymmdd format).',
    )
    parser.add_argument(
        '--last_date',
        required=True,
        help='Last day (yyyymmdd format).',
    )
    parser.add_argument(
        '--users_ids',
        default=[],
        nargs='+',
        help='List of user ids whose API consumption you want to check out. Check https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/GTI_group_admins_API_guide.md Requirements. '
        'If parameter not specified, the API consumption of all members of the group will be provided.',
    )
    args = parser.parse_args()

    if days_from_date(args.start_date) <= 30:
        raise Exception('Only the last 30 days of onsumption are available. Please adjust the dates!\n')

    users_ids = args.users_ids
    if not args.users_ids:
        users_ids = get_group_users(args.apikey, args.group_id)

    for user_id in users_ids:
        print(f'USER: {user_id}')
        pprint(
            get_user_api_consumption(
                args.apikey, user_id, args.start_date, args.last_date
            )
        )
        print('\n')

if __name__ == '__main__':
    main()
