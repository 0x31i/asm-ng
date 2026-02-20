from spiderfoot import SpiderFootPlugin, SpiderFootEvent
import re
import requests
import time
from typing import Optional, List, Dict


class sfp_4chan(SpiderFootPlugin):
    """
    SpiderFoot plugin to search 4chan boards for posts mentioning the target.
    """

    meta = {
        'name': "4chan Monitor",
        'summary': "Searches 4chan boards for posts mentioning the scan target.",
        'flags': [],
        'useCases': ["Passive", "Investigate"],
        'group': ["Passive", "Investigate"],
        'categories': ["Social Media"],
        'dataSource': {
            'name': '4chan',
            'summary': '4chan JSON API for board monitoring',
            'model': 'FREE_NOAUTH_LIMITED',
            'apiKeyInstructions': [
                'No API key required for public board monitoring.'
            ]
        }
    }

    opts = {
        "boards": "pol,b,g,k,biz",  # Comma-separated board names (e.g. pol,b)
        "max_threads": 10
    }

    optdescs = {
        "boards": "Comma-separated list of 4chan board names to search.",
        "max_threads": "Maximum number of threads to fetch per board."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.opts.update(userOpts)
        self._seen_posts = set()

    def watchedEvents(self) -> List[str]:
        return ["ROOT"]

    def producedEvents(self) -> List[str]:
        return ["FOURCHAN_POST"]

    def _fetch_catalog(self, board: str) -> Optional[List[Dict]]:
        url = f"https://a.4cdn.org/{board}/catalog.json"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            self.sf.error(f"Failed to fetch catalog for board {board}: {resp.status_code}")
        except Exception as e:
            self.sf.error(f"Exception fetching catalog for board {board}: {e}")
        return None

    def _fetch_thread(self, board: str, thread_id: int) -> Optional[Dict]:
        url = f"https://a.4cdn.org/{board}/thread/{thread_id}.json"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            self.sf.error(f"Failed to fetch thread {thread_id} on board {board}: {resp.status_code}")
        except Exception as e:
            self.sf.error(f"Exception fetching thread {thread_id} on board {board}: {e}")
        return None

    def _build_search_terms(self, target: str) -> list:
        """Build a list of search terms from the scan target.

        For a domain like 'chchcheckit.com', produces:
          - 'chchcheckit.com'  (full domain)
          - 'chchcheckit'      (domain without TLD)
        """
        terms = [target.lower()]

        # Strip common prefixes
        clean = target.lower()
        for prefix in ('http://', 'https://', 'www.'):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        clean = clean.rstrip('/')
        if clean != target.lower():
            terms.append(clean)

        # Add domain name without TLD (e.g. 'chchcheckit' from 'chchcheckit.com')
        parts = clean.split('.')
        if len(parts) >= 2:
            name = parts[0]
            if len(name) >= 4:  # Only if the name part is meaningful
                terms.append(name)

        return list(set(terms))

    def _post_mentions_target(self, post: dict, search_terms: list) -> bool:
        """Check if a post's text content mentions any of the search terms."""
        # Combine all text fields from the post
        text_parts = []
        for field in ('com', 'sub', 'name', 'filename'):
            val = post.get(field)
            if val:
                text_parts.append(str(val).lower())

        if not text_parts:
            return False

        combined = ' '.join(text_parts)
        # Strip HTML tags from 4chan comment HTML
        combined = re.sub(r'<[^>]+>', ' ', combined)

        return any(term in combined for term in search_terms)

    def handleEvent(self, event):
        target = event.data
        if not target:
            return

        search_terms = self._build_search_terms(target)
        self.sf.info(f"4chan: searching for target mentions: {search_terms}")

        boards = [b.strip() for b in self.opts.get("boards", "").split(",") if b.strip()]
        max_threads = int(self.opts.get("max_threads", 10))
        if not boards:
            self.sf.error("No 4chan boards specified in options.")
            return

        for board in boards:
            if self.checkForStop():
                return

            catalog = self._fetch_catalog(board)
            if not catalog:
                continue

            threads = []
            for page in catalog:
                threads.extend(page.get("threads", []))

            for thread in threads[:max_threads]:
                if self.checkForStop():
                    return

                thread_id = thread.get("no")
                if not thread_id:
                    continue

                # Quick check: does the thread OP mention the target?
                # (catalog includes OP subject/comment — skip the full
                #  thread fetch if the OP has no mention and the thread
                #  is unlikely to be relevant)
                op_dominated = not self._post_mentions_target(thread, search_terms)

                thread_data = self._fetch_thread(board, thread_id)
                if not thread_data:
                    continue

                for post in thread_data.get("posts", []):
                    if not self._post_mentions_target(post, search_terms):
                        continue

                    post_key = f"{board}-{thread_id}-{post.get('no')}"
                    if post_key in self._seen_posts:
                        continue
                    self._seen_posts.add(post_key)

                    post_info = {
                        "board": board,
                        "thread_id": thread_id,
                        "post_id": post.get("no"),
                        "subject": post.get("sub"),
                        "comment": post.get("com"),
                        "name": post.get("name"),
                        "time": post.get("time"),
                        "trip": post.get("trip"),
                        "filename": post.get("filename"),
                        "ext": post.get("ext"),
                        "rest": post
                    }
                    self.sf.debug(f"Emitting FOURCHAN_POST event: {post_info}")
                    post_event = SpiderFootEvent(
                        "FOURCHAN_POST",
                        str(post_info),
                        self.__class__.__name__,
                        event
                    )
                    self.notifyListeners(post_event)

                time.sleep(1)  # Respect API rate limit

    def shutdown(self):
        pass
