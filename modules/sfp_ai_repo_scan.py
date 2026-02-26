# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_repo_scan
# Purpose:     Scan public code repositories for AI model files, leaked AI API
#              keys, and AI framework usage in README/documentation.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_repo_scan(SpiderFootPlugin):

    meta = {
        'name': "AI Repository Scanner",
        'summary': "Scan public code repositories for AI model files, leaked "
                   "AI API keys, and AI configuration artifacts. Checks GitHub "
                   "repository contents for model weights (.onnx, .pt, "
                   ".safetensors, .gguf, etc.), scans for exposed AI provider "
                   "API keys (OpenAI, Anthropic, HuggingFace, Groq, and more), "
                   "and identifies AI framework usage in README files.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://github.com",
            'model': "FREE_AUTH_LIMITED",
            'description': "Checks public GitHub repositories for AI-related "
                           "artifacts including model weight files, leaked AI "
                           "service API keys, AI framework references, and "
                           "configuration files that reveal AI infrastructure.",
        }
    }

    # File extensions and names indicating AI model files
    AI_FILE_PATTERNS = [
        '.onnx', '.pt', '.pth', '.safetensors', '.pkl', '.h5', '.pb',
        'Modelfile', '.gguf', '.ggml', '.bin', 'config.json',
        'tokenizer.json', 'model.safetensors',
    ]

    # Distinctive API key patterns: (provider_name, regex_pattern)
    AI_KEY_PATTERNS = [
        ('OpenAI', r'sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}'),
        ('OpenAI Project', r'sk-proj-[a-zA-Z0-9_-]{40,}'),
        ('Anthropic', r'sk-ant-[a-zA-Z0-9_-]{40,}'),
        ('HuggingFace', r'hf_[a-zA-Z0-9]{30,}'),
        ('Replicate', r'r8_[a-zA-Z0-9]{30,}'),
        ('Groq', r'gsk_[a-zA-Z0-9]{50,}'),
        ('Fireworks', r'fw_[a-zA-Z0-9]{30,}'),
        ('Deepseek', r'sk-[a-f0-9]{48,}'),
    ]

    # Keywords to detect AI framework usage in README/docs
    AI_FRAMEWORK_KEYWORDS = [
        'tensorflow', 'pytorch', 'huggingface', 'transformers', 'langchain',
        'llamaindex', 'openai', 'anthropic', 'ollama', 'vllm', 'mlflow',
        'wandb', 'weights & biases', 'model training', 'fine-tuning',
        'inference', 'embedding',
    ]

    opts = {
        'check_file_listings': True,
        'check_api_keys': True,
        'max_repos': 20,
    }

    optdescs = {
        'check_file_listings': "Check repository file listings for AI model files.",
        'check_api_keys': "Scan repository content for leaked AI API keys.",
        'max_repos': "Maximum number of repositories to scan per target.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._repo_count = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "PUBLIC_CODE_REPO",
            "AI_INFRASTRUCTURE_DETECTED",
            "LINKED_URL_EXTERNAL",
        ]

    def producedEvents(self):
        return [
            "AI_API_KEY_LEAKED",
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_MODEL_REGISTRY_EXPOSED",
        ]

    def _extract_github_repo(self, url):
        """Extract owner/repo from a GitHub URL.

        Returns:
            tuple: (owner, repo) or (None, None) if not a valid GitHub URL.
        """
        match = re.search(
            r'(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)',
            url
        )
        if match:
            owner = match.group(1)
            repo = match.group(2)
            # Strip trailing .git if present
            repo = re.sub(r'\.git$', '', repo)
            return owner, repo
        return None, None

    def _check_repo_contents(self, owner, repo, event):
        """Check repository root file listing for AI model files and .env
        examples with leaked keys.

        Fetches the GitHub API contents endpoint and inspects file names
        against AI_FILE_PATTERNS. Also fetches .env.example files to scan
        for accidentally committed API keys.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/"

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            self.debug(f"No content returned for {owner}/{repo} contents.")
            return

        try:
            files = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            self.debug(f"Failed to parse JSON for {owner}/{repo} contents.")
            return

        if not isinstance(files, list):
            self.debug(f"Unexpected contents response for {owner}/{repo}.")
            return

        # Check file names against AI model file patterns
        ai_files_found = []
        env_example_files = []

        for entry in files:
            if self.checkForStop():
                return

            name = entry.get('name', '')
            if not name:
                continue

            # Check for AI model files
            for pattern in self.AI_FILE_PATTERNS:
                if name == pattern or name.endswith(pattern):
                    ai_files_found.append(name)
                    break

            # Track .env.example or similar files for key scanning
            if name in ('.env.example', '.env.sample', '.env.template',
                        '.env.local', '.env'):
                env_example_files.append(entry)

        # Emit AI_MODEL_REGISTRY_EXPOSED if model files found
        if ai_files_found:
            detail = (f"AI model files found in github.com/{owner}/{repo}: "
                      f"{', '.join(ai_files_found[:15])}")
            if len(ai_files_found) > 15:
                detail += f" ... (+{len(ai_files_found) - 15} more)"

            evt = SpiderFootEvent(
                "AI_MODEL_REGISTRY_EXPOSED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

        # Scan .env example files for leaked API keys
        if self.opts['check_api_keys'] and env_example_files:
            for env_entry in env_example_files:
                if self.checkForStop():
                    return

                download_url = env_entry.get('download_url', '')
                if not download_url:
                    continue

                env_res = self.sf.fetchUrl(
                    download_url,
                    timeout=15,
                    useragent=self.opts.get('_useragent', 'ASM-NG')
                )

                if not env_res or not env_res.get('content'):
                    continue

                content = env_res['content']
                self._scan_content_for_keys(
                    content, owner, repo, env_entry.get('name', '.env'),
                    event)

    def _scan_content_for_keys(self, content, owner, repo, filename, event):
        """Scan text content for leaked AI API keys and emit events."""
        for provider, pattern in self.AI_KEY_PATTERNS:
            if self.checkForStop():
                return

            matches = re.findall(pattern, content)
            for match in matches:
                # Mask the key for safety: show first 8 and last 4 chars
                if len(match) > 12:
                    masked = match[:8] + '...' + match[-4:]
                else:
                    masked = match[:4] + '...'

                detail = (f"{provider} API key leaked in "
                          f"github.com/{owner}/{repo}/{filename}: {masked}")

                key = f"key:{provider}:{match[:12]}"
                if key in self.results:
                    continue
                self.results[key] = True

                evt = SpiderFootEvent(
                    "AI_API_KEY_LEAKED",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)

    def _check_repo_readme(self, owner, repo, event):
        """Fetch the repository README and scan for AI framework keywords.

        Uses the GitHub API readme endpoint with raw content accept header
        to get the plaintext README content, then checks for mentions of
        AI frameworks to emit AI_INFRASTRUCTURE_DETECTED events.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/readme"

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG'),
            headers={
                'Accept': 'application/vnd.github.raw'
            }
        )

        if not res or not res.get('content'):
            self.debug(f"No README found for {owner}/{repo}.")
            return

        content = res['content'].lower()
        found_keywords = []

        for keyword in self.AI_FRAMEWORK_KEYWORDS:
            if keyword in content:
                found_keywords.append(keyword)

        if found_keywords:
            detail = (f"AI framework references found in "
                      f"github.com/{owner}/{repo} README: "
                      f"{', '.join(found_keywords)}")

            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # Don't recurse on our own AI_INFRASTRUCTURE_DETECTED events
        if eventName == "AI_INFRASTRUCTURE_DETECTED":
            return

        # For LINKED_URL_EXTERNAL, only process GitHub/GitLab URLs
        if eventName == "LINKED_URL_EXTERNAL":
            if 'github.com' not in eventData and 'gitlab.com' not in eventData:
                return

        # Extract owner/repo from the URL
        owner, repo = self._extract_github_repo(eventData)
        if not owner or not repo:
            self.debug(f"Could not extract owner/repo from: {eventData}")
            return

        # Dedup by repo
        dedup_key = f"repo:{owner}/{repo}"
        if dedup_key in self.results:
            self.debug(f"Already scanned {owner}/{repo}, skipping.")
            return
        self.results[dedup_key] = True

        # Respect max_repos limit
        if self._repo_count >= self.opts['max_repos']:
            self.debug(f"Reached max_repos limit ({self.opts['max_repos']}), "
                       f"skipping {owner}/{repo}.")
            return
        self._repo_count += 1

        self.info(f"Scanning repository: github.com/{owner}/{repo}")

        # Check repository file listings for AI model files
        if self.opts['check_file_listings']:
            if self.checkForStop():
                return
            self._check_repo_contents(owner, repo, event)

        # Check README for AI framework keywords
        if self.checkForStop():
            return
        self._check_repo_readme(owner, repo, event)


# End of sfp_ai_repo_scan class
