# Google Threat Intelligence group administrators API walkthrough guide

The purpose of this project is to provide examples of the most common use cases that Google Threat Intelligence group administrators may find useful, with a focus on the Google Threat Intelligence API v3.

## Requirements

Bellow use case code snippets may require some of the following parameters:

* Google Threat Intelligence group ID -> check it on the [landing page](https://www.virustotal.com/gui/home/search) -> your name at the top right corner -> **My group** option -> **GROUP PREFERENCES** section -> **Group ID** field.
* Google Threat Intelligence user ID -> check it on the [landing page](https://www.virustotal.com/gui/home/search) -> your name at the top right corner -> **My group** option -> **Group members** section -> **User sub-section** and by clicking on any user to pivot to its **USER PROFILE** where user ID is near the user avatar.
* Google Threat Intelligence service account ID -> check it on the [landing page](https://www.virustotal.com/gui/home/search) -> your name at the top right corner -> **My group** option -> **Service accounts** section.
* Google Threat Intelligence user API key -> check it on the [landing page](https://www.virustotal.com/gui/home/search) -> your name at the top right corner -> **API key** option -> **GOOGLE THREAT INTELLIGENCE API KEY** section.

## Use cases
* <a name="group-members-management">Group members management
	* Getting group members
		- [Getting the list of users and service accounts](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/getting_group_users_and_service_accounts.py)
		- [Getting the list of users with 2FA not enabled](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/getting_users_without_2fa.py)
		- [Getting the list of potentially unauthorized administrators](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/getting_potentially_unauthorized_admins.py)
	* <a name="users-management">Users management
		- [Adding new user to an existing Google Threat Intelligence group](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/adding_users_to_group.py)
		- [Removing user from a Google Threat Intelligence group](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/remove_users_from_group.py)
		- [Managing user privileges or role](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/managing_users_privileges.py)
		- [Managing user API allowance](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/managing_users_api_allowance.py)

* <a name="consumption">Consumption
	* <a name="virustotal-enterprise-features-consumption">Google Threat Intelligence features consumption
		- [Getting current month group overall consumption](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/getting_group_features_current_month_consumption.py)
		- [Getting users individual consumption](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/getting_user_features_current_month_consumption.py)
	* <a name="api-consumption">Google Threat Intelligence API consumption
		- [Getting group overall API consumption](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/getting_group_api_consumption.py)
		- [Getting users individual API consumption](https://github.com/VirusTotal/gti-use-cases/blob/main/admins_guide/getting_user_api_consumption.py)
