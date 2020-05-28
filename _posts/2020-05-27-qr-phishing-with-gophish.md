---
layout: post
title: "QR phishing with GoPhish"
tags: qr phishing gophish
---

Edit: Created a [repo for this](https://github.com/ongyuann/qr-with-gophish).

So recently I helped out a colleague whose client wanted to use QR codes for their phishing campaign. 

Problem: colleague's platform of choice, GoPhish, doesn't natively support QR code phishing.

From a technical point of view, this problem can get tricky for one very good reason: We don't want to break the platform's code.

Thankfully the colleague had contacted GoPhish's authors for a solution:
  
<img src="https://raw.githubusercontent.com/ongyuann/ongyuann.github.io/master/images/gophish_qr.jpg" alt="GoPhish actually rocks" class="inline"/>
  
  
It definitely seemed workable, and best part - it doesn't mess with the platform's code. So I got down to making the suggestions a reality. 

For the remainder of this post I divide my workings according to the suggested steps:

### Create a campaign, in your emails insert an image with src `http://<yourserver>/qr/{{.rid}}.jpg`

This is easy enough. Ultimately the src I used that worked for me was:
```
<img src="http://<ur_phishing_site>/static/qr/{{.RId}}.png" alt="it works!" width="500" height="500">
```
Note: 'RId' instead of 'rid'. `/static/qr/` instead of `/qr/`. Also insert your own phishing URL and alt message.

### API into the campaign grabbing all the URLs 

Author Note: This is to be done _after_ the campaign is launched.

Why?

The way GoPhish tracks victims is to generate a Result ID (RID) for each victim right before the email is sent out. This is done on-the-fly individually for each victim, so there's no way we can extract all RIDs and mass produce them _before_ GoPhish sends out the emails. That's why we can only mass-grab the RIDs and mass-produce the QR codes _after_ the campaign is launched.

GoPhish API allows you to API into an active campaign to grab all sorts of 'details'. In these details contain the RID (i.e. Result ID), which is what we need in order to generate unique QR codes for each victim.

This `curl` command does exactly that, with a few manipulations to extract only the RID from the API response. 
<sub><sup>(Disclaimer: the extraction is not perfect but does its job almost perfectly)</sup></sub>
```
curl localhost:3333/api/campaigns/<campaign_id>/results -H "Authorization: <ur_api_token>" | grep "id" | grep -v "campaign" | cut -d":" -f2 | cut -d'"' -f2
```
Note: Insert your own campaign ID, which you can observe in the URL right after you launch a new campaign.

Source: GoPhish API docs:
```
https://docs.getgophish.com/api-documentation/campaigns
```

### Foreach email use the QR library above to create `{{.rid}}.jpg`

Instead of using the QR library in the suggestion, I captured the API call to `qr-generator.qrcode.studio` when making a sample QR code, and just swapped the URL for my liking. Credit to www.qrcode-monkey.com for the awesome free service.

An example: Generating QR code via API and saving to 'test.png':
```
curl -X GET "https://qr-generator.qrcode.studio/qr/custom?download=true&file=png&data=https%3A%2F%2Fwww.qrcode-monkey.com&size=1000&config=%7B%22body%22%3A%22square%22%2C%22eye%22%3A%22frame0%22%2C%22eyeBall%22%3A%22ball0%22%2C%22erf1%22%3A%5B%5D%2C%22erf2%22%3A%5B%5D%2C%22erf3%22%3A%5B%5D%2C%22brf1%22%3A%5B%5D%2C%22brf2%22%3A%5B%5D%2C%22brf3%22%3A%5B%5D%2C%22bodyColor%22%3A%22%23000000%22%2C%22bgColor%22%3A%22%23FFFFFF%22%2C%22eye1Color%22%3A%22%23000000%22%2C%22eye2Color%22%3A%22%23000000%22%2C%22eye3Color%22%3A%22%23000000%22%2C%22eyeBall1Color%22%3A%22%23000000%22%2C%22eyeBall2Color%22%3A%22%23000000%22%2C%22eyeBall3Color%22%3A%22%23000000%22%2C%22gradientColor1%22%3A%22%22%2C%22gradientColor2%22%3A%22%22%2C%22gradientType%22%3A%22linear%22%2C%22gradientOnEyes%22%3A%22true%22%2C%22logo%22%3A%22%22%2C%22logoMode%22%3A%22default%22%7D" --output test.png
```

Decoded 'data' field (for reference):
```
https://www.qrcode-monkey.com&size=1000&config={"body":"square","eye":"frame0","eyeBall":"ball0","erf1":[],"erf2":[],"erf3":[],"brf1":[],"brf2":[],"brf3":[],"bodyColor":"#000000","bgColor":"#FFFFFF","eye1Color":"#000000","eye2Color":"#000000","eye3Color":"#000000","eyeBall1Color":"#000000","eyeBall2Color":"#000000","eyeBall3Color":"#000000","gradientColor1":"","gradientColor2":"","gradientType":"linear","gradientOnEyes":"true","logo":"","logoMode":"default"}
```

Of course, we won't be using `curl` to generate the QR images one by one - that's absurd. Ultimately we'll script the whole thing up and automate all the steps (see end of post).

### Copy all the generated QR images into your server's webroot

According to this [GoPhish issue](https://github.com/gophish/gophish/issues/220), static images can be stored at the `static/endpoint` directory at the GoPhish webroot. So I create a folder called `qr` in that directory and throw all our newly created QR images there. 

You can try throwing stuff there yourself and see if you can reach them at `http://<ur_phishing_site>/static/<ur_stuff>`

Works for you? Good. Now let's automate everything.

### Automating everything:
```
#!/usr/bin/python3

import requests
import os

campaign_id = '12' #change this - take from campaign url
phishing_url = 'http://<ur_phishing_site>/?rid=' #change to landing page url

gophish_webroot = '/home/ubuntu/go/src/github.com/gophish/gophish' #check this - make sure it's right
static_images_dir = '/static/endpoint/qr/'

auth_header = {'Authorization':'<ur_api_token>'} #check this - take from gophish account page
local_url = 'http://127.0.0.1:3333/api/campaigns/' + campaign_id + "/results"

r = requests.get(local_url,headers=auth_header)

def grep_rid(r):
    rid = []
    for i in r.iter_lines():
        i = i.decode('utf-8')
        if "details" in i:
            continue
        if "id" in i:
            if "campaign" in i:
                continue
            else:
                i = i.split()[1].replace('"','').replace(',','')
                if len(i) <= 6:
                    continue
                rid.append(i)
    #print (rid)
    return rid

rid = grep_rid(r) #array of rids from chosen campaign

def make_qr(rid):
    qr_dir = gophish_webroot + static_images_dir
    if not os.path.exists(qr_dir):
        os.makedirs(qr_dir)
        print ('[+] created qr directory at ' + qr_dir)
    else:
        os.system('rm ' + qr_dir + '*') #comment this if running multiple qr-code campaigns simultaneously
        print ('[+] cleared files at ' + qr_dir) #this too

    for i in rid:
        qr_file = qr_dir + i + '.png'
        url = phishing_url + i
        url = '"'+'https://qr-generator.qrcode.studio/qr/custom?download=true&file=png&data=' + url
        url += '&size=1000&config=%7B%22body%22%3A%22square%22%2C%22eye%22%3A%22frame0%22%2C%22eyeBall%22%3A%22ball0%22%2C%22erf1%22%3A%5B%5D%2C%22erf2%22%3A%5B%5D%2C%22erf3%22%3A%5B%5D%2C%22brf1%22%3A%5B%5D%2C%22brf2%22%3A%5B%5D%2C%22brf3%22%3A%5B%5D%2C%22bodyColor%22%3A%22%23000000%22%2C%22bgColor%22%3A%22%23FFFFFF%22%2C%22eye1Color%22%3A%22%23000000%22%2C%22eye2Color%22%3A%22%23000000%22%2C%22eye3Color%22%3A%22%23000000%22%2C%22eyeBall1Color%22%3A%22%23000000%22%2C%22eyeBall2Color%22%3A%22%23000000%22%2C%22eyeBall3Color%22%3A%22%23000000%22%2C%22gradientColor1%22%3A%22%22%2C%22gradientColor2%22%3A%22%22%2C%22gradientType%22%3A%22linear%22%2C%22gradientOnEyes%22%3A%22true%22%2C%22logo%22%3A%22%22%2C%22logoMode%22%3A%22default%22%7D'
        url = url + '"' + ' --output ' + qr_file
        os.system('curl -s -X GET ' + url)
        print ('[+] created qr code at ' + qr_file)
    print ('[+] done.')
    pass

make_qr(rid)
```

Do a happy dance if it worked for ya.
