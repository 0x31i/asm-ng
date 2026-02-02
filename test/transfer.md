```
1. Check if workspace data exists in the database:

sqlite3 /home/kali/Desktop/ASM-TEST/spiderfoot/data/spiderfoot.db "SELECT * FROM tbl_workspaces;"

2. Check if the table exists:

sqlite3 /home/kali/Desktop/ASM-TEST/spiderfoot/data/spiderfoot.db ".tables"

3. Check for any errors in browser console:

Open browser DevTools (F12)
Go to Console tab
Look for any JavaScript errors when loading the Workspaces page
```
