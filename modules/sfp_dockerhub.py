# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_dockerhub
# Purpose:     Search Docker Hub for container images associated with the target,
#              with focus on identifying AI/ML-related images.
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


class sfp_dockerhub(SpiderFootPlugin):

    meta = {
        'name': "Docker Hub",
        'summary': "Search Docker Hub for container images associated with the target, with focus on AI/ML images.",
        'flags': [],
        'useCases': ["Footprint", "Passive", "AI Attack Surface"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://hub.docker.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://docs.docker.com/docker-hub/api/latest/"
            ],
            'favIcon': "https://hub.docker.com/favicon.ico",
            'logo': "https://hub.docker.com/favicon.ico",
            'description': "Docker Hub is the world's largest container image "
                "repository. This module searches for public images published "
                "by the target organization and flags AI/ML-related containers.",
        }
    }

    # Default options
    opts = {
        'delay': 1.0,
        'max_results': 50,
        'ai_only': False,
    }

    # Option descriptions
    optdescs = {
        'delay': "Delay between API requests in seconds.",
        'max_results': "Maximum results to process per query.",
        'ai_only': "Only report images that appear to be AI/ML related.",
    }

    results = None
    errorState = False

    # AI/ML keywords to match in image names and descriptions
    AI_KEYWORDS = [
        'pytorch', 'tensorflow', 'keras', 'vllm', 'ollama', 'triton',
        'cuda', 'gpu', 'ml', 'ai', 'model', 'inference', 'transformers',
        'langchain', 'sagemaker', 'jupyter', 'notebook', 'huggingface',
        'mlflow', 'ray', 'gradio', 'onnx', 'tensorrt', 'deepspeed',
        'torchserve', 'bentoml', 'comfyui', 'stable-diffusion',
        'llama', 'mistral', 'openai', 'anthropic', 'llm',
    ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "COMPANY_NAME", "USERNAME"]

    def producedEvents(self):
        return ["AI_INFRASTRUCTURE_DETECTED", "SOFTWARE_USED"]

    def _isAiRelated(self, name, description):
        """Check if an image name or description contains AI/ML keywords.

        Args:
            name: The repository/image name.
            description: The repository description.

        Returns:
            A list of matched AI keywords, or an empty list.
        """
        text = f"{name} {description}".lower()
        matched = []
        for kw in self.AI_KEYWORDS:
            if kw in text:
                matched.append(kw)
        return matched

    def _buildImageInfo(self, item):
        """Build a human-readable string describing a Docker Hub repository.

        Args:
            item: A dict from the Docker Hub API response.

        Returns:
            A formatted string with image details, or None if incomplete.
        """
        repo_name = item.get('repo_name') or item.get('name')
        if not repo_name:
            return None

        namespace = item.get('namespace', '')
        description = item.get('short_description') or item.get('description') or ''
        star_count = item.get('star_count', 0)
        pull_count = item.get('pull_count', 0)
        is_official = item.get('is_official', False)

        # Build a full image reference
        if namespace and namespace != 'library':
            full_name = f"{namespace}/{repo_name}"
        else:
            full_name = repo_name

        lines = [
            f"Docker Image: {full_name}",
            f"URL: https://hub.docker.com/r/{full_name}" if namespace and namespace != 'library'
            else f"URL: https://hub.docker.com/_/{repo_name}",
        ]

        if description:
            lines.append(f"Description: {description[:200]}")
        if is_official:
            lines.append("Official: Yes")
        if star_count:
            lines.append(f"Stars: {star_count}")
        if pull_count:
            lines.append(f"Pulls: {pull_count}")

        return "\n".join(lines)

    def _searchDockerHub(self, query):
        """Search Docker Hub for repositories matching a query.

        Args:
            query: The search term.

        Returns:
            A list of repository dicts from the API, or an empty list.
        """
        encoded = urllib.parse.quote(query)
        page_size = min(self.opts['max_results'], 100)
        url = f"https://hub.docker.com/v2/search/repositories/?query={encoded}&page_size={page_size}"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.error(f"Unable to fetch {url}")
            return []

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from Docker Hub: {e}")
            return []

        if not isinstance(data, dict):
            return []

        results = data.get('results', [])
        if not isinstance(results, list):
            return []

        return results[:self.opts['max_results']]

    def _fetchUserRepos(self, namespace):
        """Fetch public repositories for a Docker Hub user/organization namespace.

        Args:
            namespace: The Docker Hub username or organization.

        Returns:
            A list of repository dicts from the API, or an empty list.
        """
        encoded = urllib.parse.quote(namespace)
        page_size = min(self.opts['max_results'], 100)
        url = f"https://hub.docker.com/v2/repositories/{encoded}/?page_size={page_size}"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.debug(f"Unable to fetch repos for namespace {namespace}")
            return []

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response for namespace {namespace}: {e}")
            return []

        if not isinstance(data, dict):
            return []

        results = data.get('results', [])
        if not isinstance(results, list):
            return []

        return results[:self.opts['max_results']]

    def _processResults(self, results, event):
        """Process a list of Docker Hub repository results, emitting events.

        For each image, emit SOFTWARE_USED. If AI-related keywords are found,
        also emit AI_INFRASTRUCTURE_DETECTED.

        Args:
            results: List of repository dicts from the Docker Hub API.
            event: The parent SpiderFootEvent.
        """
        for item in results:
            if self.checkForStop():
                return

            if not isinstance(item, dict):
                continue

            repo_name = item.get('repo_name') or item.get('name')
            if not repo_name:
                continue

            namespace = item.get('namespace', '')
            if namespace and namespace != 'library':
                dedup_key = f"{namespace}/{repo_name}"
            else:
                dedup_key = repo_name

            if dedup_key in self.results:
                self.debug(f"Already processed Docker image {dedup_key}, skipping.")
                continue
            self.results[dedup_key] = True

            description = item.get('short_description') or item.get('description') or ''
            ai_keywords = self._isAiRelated(repo_name, description)
            image_info = self._buildImageInfo(item)

            if image_info is None:
                continue

            # If ai_only is set, skip non-AI images entirely
            if self.opts['ai_only'] and not ai_keywords:
                continue

            # Emit SOFTWARE_USED for all discovered images
            evt = SpiderFootEvent(
                "SOFTWARE_USED", image_info,
                self.__name__, event)
            self.notifyListeners(evt)

            # Emit AI_INFRASTRUCTURE_DETECTED if AI keywords matched
            if ai_keywords:
                keywords_str = ", ".join(sorted(set(ai_keywords)))
                ai_detail = (
                    f"Docker Hub AI/ML image: {dedup_key} "
                    f"(keywords: {keywords_str})"
                )
                if description:
                    ai_detail += f"\nDescription: {description[:200]}"

                evt_ai = SpiderFootEvent(
                    "AI_INFRASTRUCTURE_DETECTED", ai_detail,
                    self.__name__, event)
                self.notifyListeners(evt_ai)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Already did a search for {eventData}, skipping.")
            return

        self.results[eventData] = True

        if eventName == "DOMAIN_NAME":
            # Extract the keyword portion of the domain (e.g. "example" from "example.com")
            keyword = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
            if not keyword:
                self.debug(f"Could not extract keyword from domain {eventData}")
                return

            self.debug(f"Searching Docker Hub for domain keyword: {keyword}")
            results = self._searchDockerHub(keyword)
            self._processResults(results, event)

            # Also try fetching the namespace directly in case
            # the organization has a Docker Hub account matching the keyword
            time.sleep(self.opts['delay'])
            namespace_results = self._fetchUserRepos(keyword)
            self._processResults(namespace_results, event)

        elif eventName == "COMPANY_NAME":
            self.debug(f"Searching Docker Hub for company: {eventData}")
            results = self._searchDockerHub(eventData)
            self._processResults(results, event)

        elif eventName == "USERNAME":
            self.debug(f"Fetching Docker Hub repos for user: {eventData}")
            # First try the namespace endpoint for direct user repos
            results = self._fetchUserRepos(eventData)
            self._processResults(results, event)

            # Also do a search in case the username appears in other repos
            time.sleep(self.opts['delay'])
            search_results = self._searchDockerHub(eventData)
            self._processResults(search_results, event)

        time.sleep(self.opts['delay'])


# End of sfp_dockerhub class
