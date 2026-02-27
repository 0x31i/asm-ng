# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_huggingface
# Purpose:     Search Hugging Face for models, datasets, and spaces associated
#              with the target organization.
#
# Author:      ASM-NG
#
# Created:     2026-02-26
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_huggingface(SpiderFootPlugin):

    meta = {
        'name': "Hugging Face",
        'summary': "Search Hugging Face for models, datasets, and spaces associated with the target.",
        'flags': [],
        'useCases': ["Footprint", "Passive", "AI Attack Surface"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://huggingface.co/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://huggingface.co/docs/hub/api"
            ],
            'favIcon': "https://huggingface.co/favicon.ico",
            'logo': "https://huggingface.co/favicon.ico",
            'description': "Hugging Face is a platform for sharing machine learning "
                           "models, datasets, and interactive ML demo spaces. This "
                           "module searches for public models, datasets, and spaces "
                           "associated with the target.",
        }
    }

    opts = {
        'delay': 1.0,
        'max_results': 50,
        'max_per_type': 20,
    }

    optdescs = {
        'delay': "Delay between API requests in seconds.",
        'max_results': "Maximum total results to process across all search queries.",
        'max_per_type': "Maximum results to request per resource type (models, datasets, spaces).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._emitted = set()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "COMPANY_NAME",
            "HUMAN_NAME",
            "USERNAME",
            "EMAILADDR",
        ]

    def producedEvents(self):
        return [
            "PUBLIC_CODE_REPO",
            "AI_INFRASTRUCTURE_DETECTED",
            "USERNAME",
        ]

    def _buildRepoInfo(self, name, url, description):
        """Build a PUBLIC_CODE_REPO event data string in the standard format."""
        return "\n".join([
            f"Name: {name}",
            f"URL: {url}",
            f"Description: {description}",
        ])

    def _searchHuggingFace(self, resource_type, query):
        """Search the Hugging Face API for a given resource type.

        Args:
            resource_type: One of 'models', 'datasets', or 'spaces'.
            query: The search query string.

        Returns:
            A list of result dicts, or an empty list on failure.
        """
        limit = self.opts.get('max_per_type', 20)
        encoded_query = urllib.parse.quote(query)
        url = f"https://huggingface.co/api/{resource_type}?search={encoded_query}&limit={limit}"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.debug(f"No content returned from Hugging Face API: {url}")
            return []

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error parsing JSON response from Hugging Face: {e}")
            return []

        if not isinstance(data, list):
            self.debug(f"Unexpected response format from Hugging Face for {resource_type}")
            return []

        return data

    def _processResults(self, resource_type, results, event):
        """Process search results from a Hugging Face API endpoint.

        For each result:
        - Emit PUBLIC_CODE_REPO with the HF URL
        - Emit AI_INFRASTRUCTURE_DETECTED
        - Emit USERNAME for the author if present

        Args:
            resource_type: One of 'models', 'datasets', or 'spaces'.
            results: List of result dicts from the HF API.
            event: The parent SpiderFootEvent.
        """
        type_labels = {
            'models': 'Model',
            'datasets': 'Dataset',
            'spaces': 'Space',
        }
        type_label = type_labels.get(resource_type, resource_type.title())
        processed = 0
        max_results = self.opts.get('max_results', 50)

        for item in results:
            if self.checkForStop():
                return

            if processed >= max_results:
                break

            if not isinstance(item, dict):
                continue

            item_id = item.get('id') or item.get('modelId')
            if not item_id:
                continue

            # Deduplicate across all searches
            dedup_key = f"{resource_type}:{item_id}"
            if dedup_key in self._emitted:
                continue
            self._emitted.add(dedup_key)

            # Build the URL
            if resource_type == 'models':
                hf_url = f"https://huggingface.co/{item_id}"
            elif resource_type == 'datasets':
                hf_url = f"https://huggingface.co/datasets/{item_id}"
            elif resource_type == 'spaces':
                hf_url = f"https://huggingface.co/spaces/{item_id}"
            else:
                hf_url = f"https://huggingface.co/{item_id}"

            # Extract metadata
            description = item.get('description')
            if not description and isinstance(item.get('cardData'), dict):
                description = item['cardData'].get('description')
            if not description:
                # Use pipeline_tag or tags as a fallback description
                pipeline_tag = item.get('pipeline_tag', '')
                tags = item.get('tags', [])
                if pipeline_tag:
                    description = f"Hugging Face {type_label} ({pipeline_tag})"
                elif tags and isinstance(tags, list):
                    description = f"Hugging Face {type_label} (tags: {', '.join(tags[:5])})"
                else:
                    description = f"Hugging Face {type_label}"

            # Extract the author (owner) from the item ID (format: "author/name")
            author = item.get('author') or item.get('owner')
            if not author and '/' in item_id:
                author = item_id.split('/')[0]

            # Emit PUBLIC_CODE_REPO
            repo_info = self._buildRepoInfo(item_id, hf_url, description)
            evt = SpiderFootEvent("PUBLIC_CODE_REPO", repo_info,
                                  self.__name__, event)
            self.notifyListeners(evt)

            # Emit AI_INFRASTRUCTURE_DETECTED
            detail = (f"Hugging Face {type_label} found: {item_id} "
                      f"({hf_url})")
            evt = SpiderFootEvent("AI_INFRASTRUCTURE_DETECTED", detail,
                                  self.__name__, event)
            self.notifyListeners(evt)

            # Emit USERNAME for the author if present and not already emitted
            if author:
                author_key = f"username:{author}"
                if author_key not in self._emitted:
                    self._emitted.add(author_key)
                    evt = SpiderFootEvent("USERNAME", author,
                                          self.__name__, event)
                    self.notifyListeners(evt)

            processed += 1

    def _searchAllTypes(self, query, event):
        """Search models, datasets, and spaces on Hugging Face for a query.

        Args:
            query: The search query string.
            event: The parent SpiderFootEvent.
        """
        for resource_type in ['models', 'datasets', 'spaces']:
            if self.checkForStop():
                return

            self.info(f"Searching Hugging Face {resource_type} for: {query}")
            results = self._searchHuggingFace(resource_type, query)

            if results:
                self._processResults(resource_type, results, event)

            time.sleep(self.opts['delay'])

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Already did a search for {eventData}, skipping.")
            return

        self.results[eventData] = True

        if eventName == "DOMAIN_NAME":
            # Extract the domain keyword (e.g., "sims" from "sims.dev")
            keyword = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
            if not keyword:
                self.debug(f"Could not extract keyword from domain: {eventData}")
                return
            self._searchAllTypes(keyword, event)

        elif eventName == "COMPANY_NAME":
            # Search directly with the company name
            self._searchAllTypes(eventData, event)

        elif eventName == "HUMAN_NAME":
            # Search for models/spaces by that author
            self._searchAllTypes(eventData, event)

        elif eventName == "USERNAME":
            # Search for models/spaces by that author/organization
            self._searchAllTypes(eventData, event)

        elif eventName == "EMAILADDR":
            # Extract the username part of the email and search
            username = eventData.split('@')[0]
            if username:
                self._searchAllTypes(username, event)


# End of sfp_huggingface class
