# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_github
# Purpose:      Identifies public code repositories in Github associated with
#               your target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_github(SpiderFootPlugin):

    meta = {
        'name': "Github",
        'summary': "Identify associated public code repositories on Github.",
        'flags': [],
        'useCases': ["Footprint", "Passive", "AI Attack Surface"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://github.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://developer.github.com/"
            ],
            'favIcon': "https://github.githubassets.com/favicons/favicon.png",
            'logo': "https://github.githubassets.com/favicons/favicon.png",
            'description': "GitHub brings together the world's largest community of "
            "developers to discover, share, and build better software.",
        }
    }

    # Default options
    opts = {
        'namesonly': True,
        'max_user_search_results': 3
    }

    # Option descriptions
    optdescs = {
        'namesonly': "Match repositories by name only, not by their descriptions. Helps reduce false positives.",
        'max_user_search_results': "Maximum number of GitHub user search results to process per query."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._found_users = set()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "USERNAME", "SOCIAL_MEDIA",
                "HUMAN_NAME", "EMAILADDR", "COMPANY_NAME"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "GEOINFO", "PUBLIC_CODE_REPO",
                "SOCIAL_MEDIA", "USERNAME"]

    # Build up repo info for use as an event
    def buildRepoInfo(self, item):
        # Get repos matching the name
        name = item.get('name')
        if name is None:
            self.debug("Incomplete Github information found (name).")
            return None

        html_url = item.get('html_url')
        if html_url is None:
            self.debug("Incomplete Github information found (url).")
            return None

        description = item.get('description')
        if description is None:
            self.debug("Incomplete Github information found (description).")
            return None

        return "\n".join([f"Name: {name}", f"URL: {html_url}", f"Description: {description}"])

    def _searchGitHubUsers(self, query):
        """Search GitHub users API and return the items list."""
        encoded_query = urllib.parse.quote(query)
        url = f"https://api.github.com/search/users?q={encoded_query}"
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.error(f"Unable to fetch {url}")
            return []

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from GitHub search: {e}")
            return []

        if ret is None or ret.get('total_count', 0) == 0:
            return []

        return ret.get('items', [])

    def _fetchUserProfile(self, login):
        """Fetch a full GitHub user profile by login."""
        res = self.sf.fetchUrl(
            f"https://api.github.com/users/{login}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response for user {login}: {e}")
            return None

    def _isTargetAssociated(self, profile):
        """Check if a GitHub profile is associated with the scan target.

        Used for fuzzy searches (HUMAN_NAME, COMPANY_NAME) to reduce
        false positives by verifying the profile links back to a
        target domain or known company.
        """
        target = self.getTarget()
        target_value = target.targetValue.lower()

        # Check if profile blog/website contains a target domain
        blog = (profile.get('blog') or '').lower()
        if blog and target_value in blog:
            return True

        # Check if profile email contains a target domain
        email = (profile.get('email') or '').lower()
        if email and target_value in email:
            return True

        # Check all target domains (including affiliates) against blog/email
        for domain in target.getNames():
            domain = domain.lower()
            if blog and domain in blog:
                return True
            if email and domain in email:
                return True

        # Check if profile company matches known company
        company = (profile.get('company') or '').lower().lstrip('@')
        if company and (target_value in company or company in target_value):
            return True

        return False

    def _emitUserRepos(self, login, event):
        """Fetch and emit PUBLIC_CODE_REPO events for a user's repos."""
        url = f"https://api.github.com/users/{login}/repos"
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.debug(f"Unable to fetch repos for {login}")
            return

        try:
            repos = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing repos JSON for {login}: {e}")
            return

        if not isinstance(repos, list):
            return

        for item in repos:
            if not isinstance(item, dict):
                continue
            repo_info = self.buildRepoInfo(item)
            if repo_info is not None:
                evt = SpiderFootEvent("PUBLIC_CODE_REPO", repo_info,
                                      self.__name__, event)
                self.notifyListeners(evt)

    def _processSearchResults(self, items, event, needs_validation=False):
        """Process GitHub user search results, emitting events for each match.

        Args:
            items: List of user items from the search API.
            event: The source SpiderFootEvent.
            needs_validation: If True, fetch full profile and check
                _isTargetAssociated before emitting.
        """
        max_results = self.opts.get('max_user_search_results', 3)
        processed = 0

        for item in items:
            if processed >= max_results:
                break

            login = item.get('login')
            if not login:
                continue

            if login.lower() in self._found_users:
                continue

            profile = self._fetchUserProfile(login)
            if profile is None or not profile.get('login'):
                continue

            if needs_validation and not self._isTargetAssociated(profile):
                self.debug(f"Skipping {login} — not associated with target")
                continue

            self._found_users.add(login.lower())
            processed += 1

            # Emit SOCIAL_MEDIA
            social_url = f"Github: <SFURL>https://github.com/{login}</SFURL>"
            evt = SpiderFootEvent("SOCIAL_MEDIA", social_url,
                                  self.__name__, event)
            self.notifyListeners(evt)

            # Emit USERNAME
            evt = SpiderFootEvent("USERNAME", login, self.__name__, event)
            self.notifyListeners(evt)

            # Emit full name
            full_name = profile.get('name')
            if full_name:
                evt = SpiderFootEvent(
                    "RAW_RIR_DATA", f"Possible full name: {full_name}",
                    self.__name__, event)
                self.notifyListeners(evt)

            # Emit location
            location = profile.get('location')
            if location and 3 <= len(location) <= 100:
                evt = SpiderFootEvent("GEOINFO", location,
                                      self.__name__, event)
                self.notifyListeners(evt)

            # Emit repos
            self._emitUserRepos(login, event)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data
        srcModuleName = event.module

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Already did a search for {eventData}, skipping.")
            return

        self.results[eventData] = True

        # --- Search-based discovery for EMAILADDR, HUMAN_NAME, COMPANY_NAME ---
        if eventName == "EMAILADDR":
            query = f"{eventData} in:email type:user"
            items = self._searchGitHubUsers(query)
            self._processSearchResults(items, event, needs_validation=False)
            return

        if eventName == "HUMAN_NAME":
            query = f"{eventData} in:name type:user"
            items = self._searchGitHubUsers(query)
            self._processSearchResults(items, event, needs_validation=True)
            return

        if eventName == "COMPANY_NAME":
            query = f'"{eventData}" type:user'
            items = self._searchGitHubUsers(query)
            self._processSearchResults(items, event, needs_validation=True)
            return

        # --- Extract name/location/repos from a known GitHub profile ---
        if eventName == "SOCIAL_MEDIA":
            try:
                network = eventData.split(": ")[0]
                url = eventData.split(": ")[1].replace(
                    "<SFURL>", "").replace("</SFURL>", "")
            except Exception as e:
                self.debug(f"Unable to parse SOCIAL_MEDIA: {eventData} ({e})")
                return

            if network != "Github":
                self.debug(
                    f"Skipping social network profile, {url}, as not a GitHub profile")
                return

            try:
                urlParts = url.split("/")
                username = urlParts[len(urlParts) - 1]
            except Exception:
                self.debug(f"Couldn't get a username out of {url}")
                return

            # Skip if already processed (prevents double work on self-loop)
            if username.lower() in self._found_users:
                self.debug(f"Already processed GitHub user {username}, skipping.")
                return

            self._found_users.add(username.lower())

            json_data = self._fetchUserProfile(username)
            if json_data is None or not json_data.get('login'):
                self.debug(f"{username} is not a valid GitHub profile")
                return

            full_name = json_data.get('name')
            if full_name:
                e = SpiderFootEvent(
                    "RAW_RIR_DATA", f"Possible full name: {full_name}",
                    self.__name__, event)
                self.notifyListeners(e)

            location = json_data.get('location')
            if location and 3 <= len(location) <= 100:
                e = SpiderFootEvent("GEOINFO", location, self.__name__, event)
                self.notifyListeners(e)

            self._emitUserRepos(username, event)
            return

        if eventName == "DOMAIN_NAME":
            username = self.sf.domainKeyword(
                eventData, self.opts['_internettlds'])
            if not username:
                return

        if eventName == "USERNAME":
            username = eventData

        self.debug(f"Looking at {username}")
        failed = False

        # Get all the repositories based on direct matches with the
        # name identified
        url = f"https://api.github.com/search/repositories?q={username}"
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.error(f"Unable to fetch {url}")
            failed = True

        if not failed:
            try:
                ret = json.loads(res['content'])
            except Exception as e:
                self.debug(f"Error processing JSON response from GitHub: {e}")
                ret = None

            if ret is None:
                self.error(
                    f"Unable to process empty response from Github for: {username}")
                failed = True

        if not failed:
            if ret.get('total_count', "0") == "0" or len(ret['items']) == 0:
                self.debug(f"No Github information for {username}")
                failed = True

        if not failed:
            for item in ret['items']:
                repo_info = self.buildRepoInfo(item)
                if repo_info is not None:
                    if self.opts['namesonly'] and username != item['name']:
                        continue

                    evt = SpiderFootEvent(
                        "PUBLIC_CODE_REPO", repo_info, self.__name__, event)
                    self.notifyListeners(evt)

        # Now look for users matching the name found
        failed = False
        url = f"https://api.github.com/search/users?q={username}"
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.error(f"Unable to fetch {url}")
            failed = True

        if not failed:
            try:
                ret = json.loads(res['content'])
                if ret is None:
                    self.error(
                        f"Unable to process empty response from Github for: {username}")
                    failed = True
            except Exception:
                self.error(
                    f"Unable to process invalid response from Github for: {username}")
                failed = True

        if not failed:
            if ret.get('total_count', "0") == "0" or len(ret['items']) == 0:
                self.debug("No Github information for " + username)
                failed = True

        if not failed:
            # For each user matching the username, get their repos
            for item in ret['items']:
                if item.get('repos_url') is None:
                    self.debug(
                        "Incomplete Github information found (repos_url).")
                    continue

                url = item['repos_url']
                res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.error(f"Unable to fetch {url}")
                    continue

                try:
                    repret = json.loads(res['content'])
                except Exception as e:
                    self.error(f"Invalid JSON returned from Github: {e}")
                    continue

                if repret is None:
                    self.error(
                        f"Unable to process empty response from Github for: {username}")
                    continue

                for item in repret:
                    if not isinstance(item, dict):
                        self.debug(
                            "Encountered an unexpected or empty response from Github.")
                        continue

                    repo_info = self.buildRepoInfo(item)
                    if repo_info is not None:
                        if self.opts['namesonly'] and item['name'] != username:
                            continue
                        if eventName == "USERNAME" and "/" + username + "/" not in item.get('html_url', ''):
                            continue

                        evt = SpiderFootEvent("PUBLIC_CODE_REPO", repo_info,
                                              self.__name__, event)
                        self.notifyListeners(evt)


# End of sfp_github class
