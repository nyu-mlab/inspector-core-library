# Privacy Trackers
The JSON files are obtained from the [DuckDuckGo repository](https://github.com/duckduckgo/tracker-blocklists/tree/main). 
We should note that `apple-tds.json` is now called `ios-tds.json'` based on [commit history](https://github.com/duckduckgo/tracker-blocklists/commits/main/web/v5/ios-tds.json).

The files are found at the following URLs:

[android-tds.json](https://github.com/duckduckgo/tracker-blocklists/blob/main/web/v5/android-tds.json)

[ios-tds.json](https://github.com/duckduckgo/tracker-blocklists/blob/main/web/v5/ios-tds.json)

## Purpose
To utilize the API, we need to know if the domain speaks to advertisers or not. 
The JSON files would help use derive this information.

## Automated Updates
We will create a workflow that will create a Pull Request if there needs to be updates to the JSON files.