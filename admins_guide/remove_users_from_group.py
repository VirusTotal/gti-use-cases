"""
**DISCLAIMER:**
    Please note that this code is for educational purposes only.
    It is not intended to be run directly in production.
    This is provided on a best effort basis.
    Please make sure the code you run does what you expect it to do.
"""

import argparse
import requests

print(
    "**DISCLAIMER:** Please note that this code is for educational purposes only. "
    "It is not intended to be run directly in production. This is provided on a best effort basis. "
    "Please make sure the code you run does what you expect it to do.\n"
)

def remove_user_from_group(apikey, group_id, user_id):
    """
    Removing user (by its user ID) from Google Threat Intelligence group.
    Google Threat Intelligence API endpoint reference: https://gtidocs.virustotal.com/reference/delete-user-from-group
    """

    url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users/{user_id}"
    headers = {"accept": "text/plain", "x-apikey": apikey}
    res = requests.delete(url, headers=headers)
    res.raise_for_status()
    print(f"User {user_id} successfully removed from the group.")

def main():
    parser = argparse.ArgumentParser(
        description="Removing user members from your Google Threat Intelligence group by their user IDs."
    )
    parser.add_argument("--apikey", required=True, help="Your Google Threat Intelligence API key")
    parser.add_argument(
        "--group_id",
        required=True,
        help="Your Google Threat Intelligence group ID. Check https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/GTI_group_admins_API_guide.md Requirements.",
    )
    parser.add_argument(
        "--users_ids",
        required=True,
        default=[],
        nargs="+",
        help="List of user ids you want to remove from your group. Check https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/GTI_group_admins_API_guide.md Requirements.",
    )
    args = parser.parse_args()

    for user_id in args.users_ids:
        remove_user_from_group(args.apikey, args.group_id, user_id)
    print("\n")

if __name__ == "__main__":
    main()
