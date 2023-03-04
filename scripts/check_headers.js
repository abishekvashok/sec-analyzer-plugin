// keys for results:
const iFramable_everywhere = "iFramable_everywhere";

// parse the given content security policy and return any potential issues
function parseContentSecurityPolicy(policy) {
    // check frame-ancestors derivative
    const sub_policies = policy.split(';');
    var sub_policies_dict = [];
    sub_policies.forEach((sub_policy) => {
        var values = sub_policy.split(' ');
        if(values.length < 2){
            return;
        }
        const name = values[0];
        values.shift();
        sub_policies_dict.push({
            key: name,
            values: values
        });
    });
    var results = [];
    // Frame ancestors
    if (sub_policies_dict["frame-ancestors"] !== undefined) {
        const frame_ancestors = sub_policies_dict["frame-ancestors"];
        iFramable = false;
        for(var i = 0; i < frame_ancestors.length; i++) {
            if(frame_ancestors[i] === "*" || frame_ancestors[i] === "https://*" || frame_ancestors[i] == "https://*") {
                iFramable = true;
                break;
            }
        }
        results.push({
            key: iFramable_everywhere,
            value: iFramable
        });
    }
    return results;
}

// parse cookie and log the name if not HTTPOnly or Secure
function checkCookie(cookie_blob) {
    var cookie_tuples = cookie_blob.split(';');
    const cookie_name = cookie_tuples[0];
    if (!cookie_name.includes('=')) {
        return;
    }
    cookie_tuples.shift();
    var HTTPOnly = false;
    var Secure = false;
    for(var i = 0; i < cookie_tuples.length; i++) {
        if (cookie_tuples[i].trim().toLowerCase() == "httponly") {
            HTTPOnly = true;
        } else if (cookie_tuples[i].trim().toLowerCase() == "secure") {
            secure = true;
        } else {
            if (HTTPOnly && secure) {
                break;
            }
        }
    }
    if (!HTTPOnly) {
        // On it's own might not be a security issue unless there is a form of xss
        console.log(`${cookie_name} is accessible to client-side scripts.`);
    }
    if (!secure) {
        // Only log as most bug bounties don't care for MITM attacks
        console.log(`${cookie_name} can be send over http.`);
    }
}

// Entry point
chrome.webRequest.onCompleted.addListener(
    function(details) {
        const headers = details.responseHeaders;
        // Flags for checks
        var XFramable = true;
        var csp_issues = [];
        // Checks
        for(var i = 0; i < headers.length; i++) {
            // X-Frame-Options are depreciated in favour of frame-ancestors CSP policy
            if(headers[i].name == "X-Frame-Options") {
                if (headers[i].value.toLowerCase().replace(' ', '') == "allow-from*") {
                    continue;
                }
                XFramable = false; // Partly depends on the value, but keeping it simple for now.
            }
            // Content-Security-Policy checks
            else if(headers[i].name == "Content-Security-Policy") {
                csp_issues = parseContentSecurityPolicy(headers[i].value)
            }
            // cookie checks
            else if(headers[i].name == "set-cookie") {
                checkCookie(headers[i].value);
            }
        }
        // Some post processing
        Xframable = (csp_issues[iFramable_everywhere] === undefined)? Xframable : csp_issues[iFramable_everywhere] && Xframable;
        // Post checking - reporting stage
        if (Xframable == true) {
            chrome.notifications.create({
                type: "basic",
                title: "The website seems iFramable",
                description: "The content security policy or the X-Frame-Options header is too permissible and allows the page to be loaded in an iFrame.",
                iconUrl: "icon.png"
            })
        }
    },
    {urls: ["<all_urls>"]},
    ["responseHeaders"]
);
