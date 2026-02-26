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

    # AI tool configuration files/directories in repo root
    AI_CONFIG_FILES = {
        'CLAUDE.md': 'Claude Code / Anthropic',
        '.claude': 'Claude Code / Anthropic',
        '.cursorrules': 'Cursor IDE',
        '.cursorignore': 'Cursor IDE',
        '.github/copilot-instructions.md': 'GitHub Copilot',
        'Modelfile': 'Ollama',
        'ollama-modelfile': 'Ollama',
        '.aider.conf.yml': 'Aider',
        '.aider.model.settings.yml': 'Aider',
        'comfyui.yaml': 'ComfyUI',
    }

    # Known AI packages in dependency files → provider label
    AI_DEPENDENCY_PACKAGES = {
        'openai': 'OpenAI',
        'anthropic': 'Anthropic',
        'langchain': 'LangChain',
        'langchain-core': 'LangChain',
        'langchain-community': 'LangChain',
        'langchain-openai': 'LangChain + OpenAI',
        'llamaindex': 'LlamaIndex',
        'llama-index': 'LlamaIndex',
        'transformers': 'HuggingFace Transformers',
        'huggingface-hub': 'HuggingFace Hub',
        'diffusers': 'HuggingFace Diffusers',
        'torch': 'PyTorch',
        'tensorflow': 'TensorFlow',
        'keras': 'Keras',
        'ollama': 'Ollama',
        'vllm': 'vLLM',
        'mlflow': 'MLflow',
        'wandb': 'Weights & Biases',
        'cohere': 'Cohere',
        'replicate': 'Replicate',
        'groq': 'Groq',
        'chromadb': 'ChromaDB',
        'pinecone-client': 'Pinecone',
        'weaviate-client': 'Weaviate',
        'qdrant-client': 'Qdrant',
        'faiss-cpu': 'FAISS',
        'faiss-gpu': 'FAISS',
        'tiktoken': 'OpenAI Tiktoken',
        'sentence-transformers': 'Sentence Transformers',
        'autogen': 'AutoGen',
        'crewai': 'CrewAI',
        '@langchain/core': 'LangChain',
        '@langchain/openai': 'LangChain + OpenAI',
        'ai': 'Vercel AI SDK',
        '@ai-sdk/openai': 'Vercel AI SDK + OpenAI',
        'openai-node': 'OpenAI Node',
    }

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
        'claude', 'claude code', 'copilot', 'cursor', 'gemini',
        'chatgpt', 'gpt-4', 'llama', 'mistral', 'groq', 'replicate',
        'cohere', 'stable diffusion',
        'rag', 'retrieval augmented', 'vector database',
        'chromadb', 'pinecone', 'weaviate', 'qdrant',
        'prompt engineering', 'model serving',
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
            "EMAILADDR",
            "USERNAME",
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
        ai_config_found = []

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

            # Check for AI tool configuration files
            if name in self.AI_CONFIG_FILES:
                ai_config_found.append(
                    f"{name} ({self.AI_CONFIG_FILES[name]})")

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

        # Emit AI_INFRASTRUCTURE_DETECTED if AI config files found
        if ai_config_found:
            detail = (f"AI tool configuration found in "
                      f"github.com/{owner}/{repo}: "
                      f"{', '.join(ai_config_found)}")

            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
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

    def _check_dependency_files(self, owner, repo, event):
        """Scan requirements.txt and package.json for known AI packages."""
        dep_files = {
            'requirements.txt': 'python',
            'package.json': 'node',
        }

        for filename, filetype in dep_files.items():
            if self.checkForStop():
                return

            url = (f"https://api.github.com/repos/{owner}/{repo}"
                   f"/contents/{filename}")

            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'ASM-NG'),
                headers={
                    'Accept': 'application/vnd.github.raw'
                }
            )

            if not res or not res.get('content'):
                continue

            content = res['content']
            found = []

            if filetype == 'python':
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # Extract package name (before ==, >=, <=, ~=, etc.)
                    pkg = re.split(r'[><=!~\[;@\s]', line)[0].lower()
                    if pkg in self.AI_DEPENDENCY_PACKAGES:
                        found.append(
                            f"{pkg} ({self.AI_DEPENDENCY_PACKAGES[pkg]})")

            elif filetype == 'node':
                try:
                    pkg_json = json.loads(content)
                except (json.JSONDecodeError, ValueError):
                    continue
                all_deps = {}
                for section in ('dependencies', 'devDependencies'):
                    all_deps.update(pkg_json.get(section, {}))
                for dep_name in all_deps:
                    dep_lower = dep_name.lower()
                    if dep_lower in self.AI_DEPENDENCY_PACKAGES:
                        found.append(
                            f"{dep_name} "
                            f"({self.AI_DEPENDENCY_PACKAGES[dep_lower]})")

            if found:
                detail = (f"AI dependencies in "
                          f"github.com/{owner}/{repo}/{filename}: "
                          f"{', '.join(found)}")

                evt = SpiderFootEvent(
                    "AI_INFRASTRUCTURE_DETECTED",
                    detail,
                    self.__class__.__name__, event)
                self.notifyListeners(evt)

    def _check_repo_contributors(self, owner, repo, event):
        """Check repository contributors for known AI bot accounts."""
        url = f"https://api.github.com/repos/{owner}/{repo}/contributors"

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            self.debug(f"No contributors data for {owner}/{repo}.")
            return

        try:
            contributors = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            self.debug(f"Failed to parse contributors for {owner}/{repo}.")
            return

        if not isinstance(contributors, list):
            return

        ai_bot_patterns = {
            'claude': 'Claude / Anthropic',
            'copilot-swe-agent': 'GitHub Copilot',
            'devin-ai': 'Devin AI',
            'coderabbit': 'CodeRabbit',
            'sweep-ai': 'Sweep AI',
            'aider': 'Aider',
        }

        found = []
        for contrib in contributors:
            if self.checkForStop():
                return

            login = contrib.get('login', '').lower()
            commits = contrib.get('contributions', 0)

            for pattern, label in ai_bot_patterns.items():
                if pattern in login:
                    display_login = contrib.get('login', login)
                    found.append(
                        f"{display_login} — {commits} commits ({label})")
                    break

        if found:
            detail = (f"AI contributor(s) in "
                      f"github.com/{owner}/{repo}: "
                      f"{', '.join(found)}")

            evt = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)

    def _check_repo_branches(self, owner, repo, event):
        """Check repository branch names for AI tool naming patterns."""
        url = (f"https://api.github.com/repos/{owner}/{repo}"
               f"/branches?per_page=100")

        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            self.debug(f"No branches data for {owner}/{repo}.")
            return

        try:
            branches = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            self.debug(f"Failed to parse branches for {owner}/{repo}.")
            return

        if not isinstance(branches, list):
            return

        ai_branch_prefixes = {
            'claude/': 'Claude Code',
            'copilot/': 'GitHub Copilot',
            'devin/': 'Devin AI',
            'sweep/': 'Sweep AI',
            'coderabbit/': 'CodeRabbit',
            'aider/': 'Aider',
            'cursor/': 'Cursor IDE',
        }

        # Group matched branches by prefix
        matches_by_prefix = {}
        for branch in branches:
            if self.checkForStop():
                return

            name = branch.get('name', '')
            name_lower = name.lower()
            for prefix, label in ai_branch_prefixes.items():
                if name_lower.startswith(prefix):
                    matches_by_prefix.setdefault(prefix, []).append(name)
                    break

        if not matches_by_prefix:
            return

        parts = []
        for prefix, names in matches_by_prefix.items():
            label = ai_branch_prefixes[prefix]
            # Show up to 3 example names, then count
            examples = ', '.join(names[:3])
            if len(names) > 3:
                examples += f" (+{len(names) - 3} more)"
            parts.append(
                f"{examples} ({len(names)} {prefix}* branches"
                f" — indicates {label} workflow)")

        detail = (f"AI-named branches in "
                  f"github.com/{owner}/{repo}: "
                  f"{'; '.join(parts)}")

        evt = SpiderFootEvent(
            "AI_INFRASTRUCTURE_DETECTED",
            detail,
            self.__class__.__name__, event)
        self.notifyListeners(evt)

    def _discover_github_by_email(self, email, event):
        """Search GitHub for users matching an email address.

        Uses the GitHub user search API with in:email qualifier to find
        the actual GitHub account linked to an email address (e.g.
        elias@sims.dev → 0x31i). Falls back to username-from-email
        if the search returns nothing.
        """
        dedup_key = f"ghemail:{email.lower()}"
        if dedup_key in self.results:
            return
        self.results[dedup_key] = True

        # Search GitHub for users with this email
        url = (f"https://api.github.com/search/users"
               f"?q={email}+in:email")
        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        found_via_email = False
        if res and res.get('content'):
            try:
                result = json.loads(res['content'])
                items = result.get('items', [])
                for item in items:
                    login = item.get('login', '')
                    if login:
                        self.info(f"GitHub email search: {email} → {login}")
                        self._discover_github_repos(login, event)
                        found_via_email = True
            except (json.JSONDecodeError, ValueError):
                pass

        # Fallback: try the email username as a GitHub username
        username = email.split('@')[0]
        if username and len(username) >= 2:
            self._discover_github_repos(username, event)

    def _discover_github_repos(self, username, event):
        """Discover GitHub repos for a username and scan each one.

        Checks if the username is a valid GitHub user, then fetches their
        public repos and runs all AI checks on each one.
        """
        dedup_key = f"ghuser:{username.lower()}"
        if dedup_key in self.results:
            self.debug(f"Already looked up GitHub user {username}, skipping.")
            return
        self.results[dedup_key] = True

        # Verify the GitHub user exists
        url = f"https://api.github.com/users/{username}"
        res = self.sf.fetchUrl(
            url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            self.debug(f"No GitHub user found for: {username}")
            return

        try:
            user_data = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            return

        if not user_data.get('login'):
            self.debug(f"{username} is not a valid GitHub user.")
            return

        actual_login = user_data['login']
        self.info(f"Found GitHub user: {actual_login} — fetching repos")

        # Fetch repos (up to 100 — respects max_repos in _scan_repo)
        repos_url = (f"https://api.github.com/users/{actual_login}"
                     f"/repos?per_page=100&sort=updated")
        res = self.sf.fetchUrl(
            repos_url,
            timeout=15,
            useragent=self.opts.get('_useragent', 'ASM-NG')
        )

        if not res or not res.get('content'):
            self.debug(f"No repos returned for GitHub user {actual_login}.")
            return

        try:
            repos = json.loads(res['content'])
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(repos, list):
            return

        for repo_obj in repos:
            if self.checkForStop():
                return

            owner = repo_obj.get('owner', {}).get('login', actual_login)
            repo_name = repo_obj.get('name', '')
            if not repo_name:
                continue

            self._scan_repo(owner, repo_name, event)

    def _scan_repo(self, owner, repo, event):
        """Run all AI checks on a single repo (with dedup and limit)."""
        dedup_key = f"repo:{owner}/{repo}"
        if dedup_key in self.results:
            self.debug(f"Already scanned {owner}/{repo}, skipping.")
            return
        self.results[dedup_key] = True

        if self._repo_count >= self.opts['max_repos']:
            self.debug(f"Reached max_repos limit ({self.opts['max_repos']}), "
                       f"skipping {owner}/{repo}.")
            return
        self._repo_count += 1

        self.info(f"Scanning repository: github.com/{owner}/{repo}")

        if self.opts['check_file_listings']:
            if self.checkForStop():
                return
            self._check_repo_contents(owner, repo, event)

        if self.checkForStop():
            return
        self._check_repo_readme(owner, repo, event)

        if self.checkForStop():
            return
        self._check_dependency_files(owner, repo, event)

        if self.checkForStop():
            return
        self._check_repo_contributors(owner, repo, event)

        if self.checkForStop():
            return
        self._check_repo_branches(owner, repo, event)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # Don't recurse on our own AI_INFRASTRUCTURE_DETECTED events
        if eventName == "AI_INFRASTRUCTURE_DETECTED":
            return

        # EMAILADDR → search GitHub by email, then fallback to username
        if eventName == "EMAILADDR":
            self._discover_github_by_email(eventData, event)
            return

        # USERNAME → discover GitHub repos directly
        if eventName == "USERNAME":
            if eventData and len(eventData) >= 2:
                self._discover_github_repos(eventData, event)
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

        self._scan_repo(owner, repo, event)


# End of sfp_ai_repo_scan class
