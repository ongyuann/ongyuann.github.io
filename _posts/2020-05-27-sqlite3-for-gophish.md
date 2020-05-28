---
layout: post
title: "Useful SQLite3 stuff for GoPhish"
tags: gophish phishing sqlite3
---

finding a string from entire sqlite3 database:
source: `https://stackoverflow.com/questions/13514509/search-sqlite-database-all-tables-and-columns`
```
for X in $(sqlite3 database.db .tables) ; do sqlite3 database.db "SELECT * FROM $X;" | grep >/dev/null 'STRING I WANT' && echo $X; done
```