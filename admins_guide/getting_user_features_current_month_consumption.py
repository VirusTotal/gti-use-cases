"""
**DISCLAIMER:**
    Please note that this code is for educational purposes only.
    It is not intended to be run directly in production.
    This is provided on a best effort basis.
    Please make sure the code you run does what you expect it to do.
"""

import argparse
from pprint import pprint
import requests

print(
    "**DISCLAIMER:** Please note that this code is for educational purposes only. "
    "It is not intended to be run directly in production. "
    "This is provided on a best effort basis. "
    "Please make sure the code you run does what you expect it to do.\n"
)

def get_group_users(apikey, group_id):
    """
    Getting group users ID list (by group ID).
    Google Threat Intelligence API endpoint reference: https://gtidocs.virustotal.com/reference/get-group-users
    """

    users = []
    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users"
    headers = {"accept": "application/json", "x-apikey": apikey}

    while url:
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        res = res.json()
        users.extend([e["id"] for e in res["data"]])
        url = res.get("links", {}).get("next", None)
    return users

def get_user_features_consumption(apikey, user_id):
    """
    Getting current month Google Threat Intelligence user features consumption by user ID.
    Google Threat Intelligence API endpoint reference: https://gtidocs.virustotal.com/reference/get-user-overall-quotas
    """

    url = f"https://www.virustotal.com/api/v3/users/{user_id}/overall_quotas"
    headers = {"accept": "application/json", "x-apikey": apikey}
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    res = res.json()
    keys = list(res.get("data", {}).keys())
    # remove group related info
    for el in keys:
        if res.get("data", {}).get(el, {}).get("group", None):
            res.get("data", {}).get(el, {}).pop("group")
    return res

def main():
    parser = argparse.ArgumentParser(
        description="Getting current month Google Threat Intelligence users features consumption."
    )
    parser.add_argument("--apikey", required=True, help="Your Google Threat Intelligence API key")
    parser.add_argument(
        "--group_id",
        required=True,
        help="Your Google Threat Intelligence group ID. Check https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/GTI_group_admins_API_guide.md Requirements.",
    )
    parser.add_argument(
        "--users_ids",
        default=[],
        nargs="+",
        help="List of user ids whose current month Google Threat Intelligence features consumption you want to check out. Check https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/GTI_group_admins_API_guide.md Requirements. "
        "If parameter not specified, the API consumption of all members of the group will be provided.",
    )
    args = parser.parse_args()

    users_ids = args.users_ids
    if not args.users_ids:
        users_ids = get_group_users(args.apikey, args.group_id)

    for user_id in users_ids:
        print(f"USER: {user_id}")
        pprint(get_user_features_consumption(args.apikey, user_id))
        print("\n")

if __name__ == "__main__":
    main()
