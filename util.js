function getItem(key){
    var value = (null == window.localStorage.getItem(key))? "" : window.localStorage.getItem(key);
    return value;
}

function setItem(key, value){
    window.localStorage.removeItem(key);
    window.localStorage.setItem(key, value);
}

function setElement(key, value){
    document.getElementById(key).value = value;
}

function getAuthToken(isConfig){
    console.log("Requesting an authorization token.");
    if("" != getItem("tenantid") && "" != getItem("clientid") && "" != getItem("secret"))
    {
        const xhr = new XMLHttpRequest();
        const authurl = "https://login.microsoftonline.com/"+  getItem("tenantid") + "/oauth2/v2.0/token"; 
        const formdata = "client_id=" + getItem("clientid") + "&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret="+  getItem("secret") + "&grant_type=client_credentials";

        // open request
        xhr.open("POST", authurl);

        // set headers
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

        // send callout
        xhr.send(formdata);

        // handle response
        xhr.onload = () =>{
            console.log("Response Recieved.");
            if(xhr.readyState == 4 && xhr.status == 200){
                const res = JSON.parse(xhr.responseText);
                // set token
                setItem("authtoken", res.access_token);
                // set token expiration (res.expires_in converted from seconds from now to miliseconds)
                setItem("exp", Date.now() + (res.expires_in * 1000));
                
                console.log("Success!")
                if(isConfig){
                    document.getElementById("output").innerHTML = "Configuration values verified and saved. You may close this window.";
                    document.getElementById("warning").innerHTML = "\n";
                }
                else{
                    classifyIOCs();
                }
            }
            else{
                console.log("Request for authorization token failed. \nStatus Code: " + xhr.status +  "\nResponse text: " + xhr.responseText);
                document.getElementById("output").innerHTML = "\n";
                document.getElementById("warning").innerHTML = "Authorization Error. Please check configuration values, console logs, and application permissions.";
                setItem("authtoken", "");
            }
        };
    }
    else{
        console.log("Get authorization token failed. Missing configuration values.");
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Authorization Error. Please check configuration values.";
    }
}
