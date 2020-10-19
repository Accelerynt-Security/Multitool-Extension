function getItem(key){
    var value = (null == window.localStorage.getItem(key))? "" : window.localStorage.getItem(key);
    if("tenantid" == key || "clientid" == key || "secret" == key || "authtoken" == key){
       value = decrypt(value);
    }
    return value;
}

function setItem(key, value){
    window.localStorage.removeItem(key);
    if("tenantid" == key || "clientid" == key || "secret" == key || "authtoken" == key){
        window.localStorage.setItem(key, encrypt(value));
    }
    else{
        window.localStorage.setItem(key, value);
    }
}

function setElement(key, value){
    document.getElementById(key).value = value;
}

// reset key and re-encrypt
function encryptionReset(){
    if("" != getItem("key") && "" != getItem("authtoken") && "" != getItem("tenantid") && "" != getItem("clientid") && "" != getItem("secret"))
    {
        var aut = getItem("authtoken");
        var ten = getItem("tenantid");
        var cli = getItem("clientid");
        var sec = getItem("secret");
        setItem("key", generateKey());
        setItem("authtoken",  aut);
        setItem("tenantid",  ten);
        setItem("clientid", cli);
        setItem("secret", sec);
    }
}

// randomly generates a key of random length
function generateKey(){
    var key = "";
    var length = randomNumber(20, 100);
    for(let i = 0; i < length; i++){
        key = key + String.fromCharCode(randomNumber(97, 122)); 
    }
    return key;
}

// return a random number in a given range
function randomNumber(min, max) {  
    return Math.round(Math.random() * (max - min) + min); 
} 

function encrypt(value){
    var keylength = getItem("key").length -1;
    var keyindex = 0;
    var result = "";
    if(value != ""){
        for(let i = 0; i < value.length; i++){
            if(keyindex == keylength){
                keyindex = 0;
            }
            var abra = getItem("key")[keyindex].charCodeAt(0);
            var kadabra = abra + value[i].charCodeAt(0);
            result += kadabra;
            result += "/"; 
            keyindex += 1;
        }
    }
    return result;
}

function decrypt(value){
    var keylength = getItem("key").length -1;
    var keyindex = 0;
    var result = "";
    if(value != ""){
        var cipher = value.split("/");
        for(let i = 0; i < cipher.length; i++){
            if(!isNaN(cipher[i]) && cipher[i] > 97){
            if(keyindex == keylength){
                keyindex = 0;
            }
            var abra = cipher[i];
            var kadabra = abra - getItem("key")[keyindex].charCodeAt(0);
            result += String.fromCharCode(kadabra);
            keyindex += 1;
            }
        }
    }
    return result;
}

// parameter indicates calling location, responses are handled accordingly
function getAuthToken(callingLocation){
    console.log("Requesting an authorization token from " + callingLocation +".");
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
                if("config" == callingLocation){
                    document.getElementById("ioc").disabled = false;
                    document.getElementById("output").innerHTML = "Configuration values verified and saved. You may close this window.";
                    document.getElementById("warning").innerHTML = "\n";
                }
                else if("extract"){
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
