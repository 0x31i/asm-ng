```
Here are the exact steps, in order. Run all of these from your local machine:

Step 1: Merge the rebrand PR on spiderfoot
https://github.com/0x31i/spiderfoot/compare/master...claude/migrate-spiderfoot-asm-ng-vQFQo

Create the PR, then squash and merge it.

Step 2: Delete all stale claude/* branches from spiderfoot
git clone https://github.com/0x31i/spiderfoot.git
cd spiderfoot

# Delete every claude/* branch from the remote
git branch -r | grep 'origin/claude/' | sed 's|origin/||' | xargs -I{} git push origin --delete {}

cd ..

Step 3: Create the asm-ng repo
gh repo create 0x31i/asm-ng --public

Step 4: Mirror spiderfoot to asm-ng
git clone --bare https://github.com/0x31i/spiderfoot.git
cd spiderfoot.git
git push --mirror https://github.com/0x31i/asm-ng.git
cd ..
rm -rf spiderfoot.git spiderfoot

Step 5: Verify
Go to https://github.com/0x31i/asm-ng — you should see:

master branch with the rebrand commit on top
No claude/* branches
Full commit history intact
After that, start a new Claude Code session pointed at 0x31i/asm-ng and we continue from there.
```
