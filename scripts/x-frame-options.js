chrome.webRequest.onCompleted.addListener(
    function(details) {
        const headers = details.responseHeaders;
        var XFramable = true;
        for(var i = 0; i < headers.length; i++) {
            if(headers[i].name == "X-Frame-Options") {
                if (headers[i].value.toLowerCase().replace(' ', '') == "allow-from*") {
                    continue;
                }
                XFramable = false; // Partly depends on the value, but keeping it simple for now.
                break;
            }
        }
        if (Xframable == true) {
            chrome.notifications.create({
                type: "basic",
                title: "X-Frame-Options header suspectible",
                description: "The X-Frame-Options header is not either set by this page or is set to allow-from *. This can lead to clickjacking attacks.",
                iconUrl: "icon.png"
            })
        }
    },
    {urls: ["<all_urls>"]},
    ["responseHeaders"]
);
