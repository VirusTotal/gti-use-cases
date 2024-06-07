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

print(
    '**DISCLAIMER:** Please note that this code is for educational purposes only. '
    'It is not intended to be run directly in production. '
    'This is provided on a best effort basis. '
    'Please make sure the code you run does what you expect it to do.\n'
)

def get_group_features_current_month_consumption(apikey, user_id):
    '''
    Getting current month Google Threat Intelligence group features consumption by user ID or user API key.
    Google Threat Intelligence API endpoint reference: https://gtidocs.virustotal.com/reference/get-user-overall-quotas
    '''

    url = f'https://www.virustotal.com/api/v3/users/{user_id}/overall_quotas'
    headers = {'accept': 'application/json', 'x-apikey': apikey}
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    res = res.json()
    pprint(res)
    keys = list(res.get('data', {}).keys())
    # remove user related info
    for el in res.get('data', {}):
        if res['data'][el].get('user', None):
            res['data'][el].pop('user')
    # remove not group related info
    for key in keys:
        if not res['data'].get(key, {}).get('group', None):
            res['data'].pop(key)
    summary = (
        f'\tSearches {res["data"]["intelligence_searches_monthly"]["group"]["used"]}'
        + f'/{res["data"]["intelligence_searches_monthly"]["group"]["allowed"]}\n'
        + f'\tDownloads {res["data"]["intelligence_downloads_monthly"]["group"]["used"]}'
        + f'/{res["data"]["intelligence_downloads_monthly"]["group"]["allowed"]}\n'
        + f'\tLivehunt rules {res["data"]["intelligence_hunting_rules"]["group"]["used"]}'
        + f'/{res["data"]["intelligence_hunting_rules"]["group"]["allowed"]}\n'
        + f'\tRetrohunt {res["data"]["intelligence_retrohunt_jobs_monthly"]["group"]["used"]}'
        + f'/{res["data"]["intelligence_retrohunt_jobs_monthly"]["group"]["allowed"]}\n'
        + f'\tDiff {res["data"]["intelligence_vtdiff_creation_monthly"]["group"]["used"]}'
        + f'/{res["data"]["intelligence_vtdiff_creation_monthly"]["group"]["allowed"]}\n'
        + f'\tPrivate scanning for files {res["data"]["private_scans_monthly"]["group"]["used"]}'
        + f'/{res["data"]["private_scans_monthly"]["group"]["allowed"]}\n'
        + f'\tPrivate scanning for URLs {res["data"]["private_urlscans_monthly"]["group"]["used"]}'
        + f'/{res["data"]["private_urlscans_monthly"]["group"]["allowed"]}\n'
    )
    return summary, res

def main():
    parser = argparse.ArgumentParser(
        description='Getting current month Google Threat Intelligence group features consumption.'
    )
    parser.add_argument('--apikey', required=True, help='Your Google Threat Intelligence API key')
    parser.add_argument(
        '--user_id',
        required=True,
        help='Your user ID. Check https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/GTI_group_admins_API_guide.md Requirements.',
    )
    args = parser.parse_args()

    summary, breakdown = get_group_features_current_month_consumption(
        args.apikey, args.user_id
    )
    print('Group features consumption summary:')
    print(f'{summary}\n')
    print('Group features consumption breakdown:')
    pprint(breakdown)

if __name__ == '__main__':
    main()
