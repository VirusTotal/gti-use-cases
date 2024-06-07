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

def get_group_api_consumption(apikey, group_id, start_date, last_date):
    '''
    Getting Google Threat Intelligence API group consumption between 2 dates (by group ID). 
        Please note that available data includes only the last 30 natural days.
    Google Threat Intelligence API endpoint reference: https://gtidocs.virustotal.com/reference/group-api-usage
    '''

    url = f'https://www.virustotal.com/api/v3/groups/{group_id}/api_usage?start_date={start_date}&end_date={last_date}'
    headers = {'accept': 'application/json', 'x-apikey': apikey}
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    res = res.json()
    # removing not consuming endpoints
    res['data'].pop('daily_endpoints_not_consuming_quota')
    # removing days with no consumption
    keys = list(res['data']['daily'].keys())
    for key in keys:
        if not res['data']['daily'].get(key):
            res['data']['daily'].pop(key)
    total = sum(res['data']['total'][e] for e in res['data']['total'])

    return (
        total,
        res['data']['total'],
        res['data']['daily'],
        res['data']['total_endpoints_not_consuming_quota'],
    )

def main():
    parser = argparse.ArgumentParser(
        description='Getting Google Threat Intelligence API group consumption between 2 dates.'
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
    args = parser.parse_args()

    if days_from_date(args.start_date) <= 30:
        raise Exception('Only the last 30 days of onsumption are available. Please adjust the dates!\n')

    (
        total,
        by_endpoint,
        by_endpoint_and_day,
        by_endpoint_not_consuming,
    ) = get_group_api_consumption(
        args.apikey, args.group_id, args.start_date, args.last_date
    )
    if total > 0:
        print(f'TOTAL {args.group_id} group API consumption: {total}\n')
        print('Consumption API endpoint breakdown:')
        pprint(by_endpoint)
        print('\n')
        print('Consumption API endpoint-day breakdown:')
        pprint(by_endpoint_and_day)
        print('\n')
        print('Not consuming API endpoint breakdown:')
        pprint(by_endpoint_not_consuming)
    else:
        print(
            f'The {args.group_id} has 0 API consumption between {args.start_date} and {args.last_date}.\n'
        )

if __name__ == '__main__':
    main()
