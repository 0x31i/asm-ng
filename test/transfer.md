```
# 1. Merge the rebrand PR on spiderfoot first (via GitHub UI)

# 2. Delete all claude/* branches from spiderfoot
git clone https://github.com/0x31i/spiderfoot.git
cd spiderfoot
git branch -r | grep 'origin/claude/' | sed 's|origin/||' | xargs -I{} git push origin --delete {}

# 3. Re-mirror to asm-ng (this replaces EVERYTHING)
cd ..
git clone --bare https://github.com/0x31i/spiderfoot.git
cd spiderfoot.git
git push --mirror https://github.com/0x31i/asm-ng.git
cd .. && rm -rf spiderfoot.git spiderfoot
```
