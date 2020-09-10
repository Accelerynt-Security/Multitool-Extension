"use strict";

document.getElementById("extract").addEventListener("click", extractIOCs);
document.getElementById("senddata").addEventListener("click", sendData);
document.getElementById("iocs").addEventListener("change", iocsChange);
document.getElementById("description").addEventListener("change", descriptionChange);
document.getElementById("confidence").addEventListener("change", confidenceChange);
document.getElementById("tlplevel").addEventListener("change", tlplevelChange);

// tracks multiple ioc submission
var multiple = false;

// loading setup
window.onload = function() {
    console.log("Azure Sentinel IOC Submission. Loading window and setting initial values.");
    // set initial values
    setItem("confidence", "50");
    setItem("tlplevel", "white");
    setElement("iocs", getItem("iocs"));
    setElement("description", getItem("description"));
    setElement("confidence", getItem("confidence"));
    setElement("tlplevel", getItem("tlplevel"));
    document.getElementById("senddata").disabled = true;
    // check validity of configuration
    if("" == getItem("authtoken")){
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Please check configuration before proceeding.";
        document.getElementById("extract").disabled = true;
    }
    else{
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "\n";
        document.getElementById("extract").disabled = false;
    }
};

// reset json body and disable submit button; re-sanitization needed to form new json for request
function handleFieldChange(){
    setItem("json", "");
    document.getElementById("senddata").disabled = true;
    document.getElementById("output").innerHTML = "\n";
    document.getElementById("warning").innerHTML = "\n";
}

// tracks changes to ioc field
function iocsChange(){
    setItem("iocs", document.getElementById("iocs").value);
    handleFieldChange();
}

// tracks changes to description field
function descriptionChange(){
    setItem("description", document.getElementById("description").value);
    handleFieldChange();
}

// tracks changes to confidence field
function confidenceChange(){
    setItem("confidence", document.getElementById("confidence").value);
    handleFieldChange();
}

// tracks changes to tlplevel field
function tlplevelChange(){
    setItem("tlplevel", document.getElementById("tlplevel").value);
    handleFieldChange();
}

// initial checks before data is parsed and packaged into json
function extractIOCs()
{
    console.log("Extracting IOCs. Running initial checks.");
    // mising configuration values
    if("" == getItem("authtoken")){
        console.log("Failed to extract IOCs. Missing configuration values.");
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Authorization Error. Please check configuration values.";
        document.getElementById("senddata").disabled = true;
    }
    // missing ioc data
    else if("" == getItem("iocs")){
        console.log("Failed to extract IOCs. Input required.");
        document.getElementById("warning").innerHTML = "Failed to extract IOCs. Input required.";
        document.getElementById("senddata").disabled = true;
    }
    // proceed with data parsing
    else{
        // get new auth token if expired
        if(getItem("exp") <= Date.now()){
            console.log("Authorization token has expired. Requesting a new one before proceeding.");
            // getAuthToken will call classifyIOCs() if/when a valid token is obtained
            getAuthToken(false);
        }
        else{
            classifyIOCs();
        }  
    }
}

// data sanitization and ioc parsing/validation/classification
function classifyIOCs()
{
    console.log("Extracting IOCs. Classifying and validating iocs.");

    // initial data parsing
    var data = getItem("iocs").split(/[ ,\n]+/);

    // track values not thrown out during classification
    var acceptedvalues = "";
    var count = 0;

    // map to hold accepted iocs and their classifications
    var iocs = new Map();

    // extract and classify ioc data
    for(let i = 0; i < data.length;  i++){
        // api does not allow more than 100 IOCs submitted at one time
        if(count == 100){
            break;
        }
        var entry = data[i].trim();
        if(entry.length > 2){

            // possible filehash
            if(!entry.includes(".")){
                // check for valid chars letters (a-F A-F & 0-9) and numbers only 
                var checkchars = entry.split('');
                var isvalid = true;
                for(let j = 0; j < checkchars.length; j ++){
                    var c = checkchars[j];
                    if(!c.match(/[A-Fa-f0-9]/)){
                        isvalid = false;
                    }
                }
                if(isvalid && (entry.length == 32 || entry.length == 64)){
                    console.log("IOC: "+ entry + " classified as a filehash.");
                    acceptedvalues += entry + "\n";
                    count += 1;
                    iocs.set(entry, "filehash");
                }   
            }

            // possible ip
            else if(!entry.match(/[A-Za-z]/)){
                // check for and remove port if found
                if(entry.indexOf(":") != -1){
                    entry = entry.substr(0, entry.indexOf(":"));
                }
                // check for valid ip range
                var ipcheck = entry.split(".");
                var isvalid = true;
                for(let j=0; j < ipcheck.length; j++){
                    var number = parseInt(ipcheck[j]);
                    if(ipcheck.length != 4 || isNaN(ipcheck[j]) || number < 0 ||  number > 255){
                        isvalid = false;
                    }
                }
                if(isvalid){
                    console.log("IOC: "+ entry + " classified as an ip.");
                    acceptedvalues += entry + "\n";
                    count += 1;
                    iocs.set(entry, "ip");
                }
            }

            // possible domain
            else if(!entry.includes("..") && entry.split(".").length >= 2) {
                //  !entry.includes("http://") && !entry.includes("https://")
                // domain parsing
                if(entry.indexOf("://") != -1){
                    entry = entry.substr(entry.indexOf("://")+3, entry.length-1);
                }
                if(entry.indexOf("www.") != -1){
                    entry = entry.substr(entry.indexOf("www.")+4, entry.length-1);
                }
                if(entry.indexOf("/") != -1){
                    entry = entry.substr(0, entry.indexOf("/"));
                }
                // check for valid domain
                var domaincheck = entry.split(".");
                var subdomaincount = 0;
                for(let j=0; j < domaincheck.length; j++){
                    if(0 < domaincheck[j].length){
                        subdomaincount += 1;
                    }
                }
                if(subdomaincount > 1 && !entry.match(/[@#%~]/))
                {
                    console.log("IOC: "+ entry + " classified as a domain.");
                    acceptedvalues += entry + "\n";
                    count += 1;
                    iocs.set(entry, "domain");
                }
            }

        }    
    }

    // set field with accepted values
    setElement("iocs", acceptedvalues);

    // return if no data to proceed with
    if("" == acceptedvalues)
    {
        console.log("No valid ioc enteries found.");
        document.getElementById("warning").innerHTML = "Failure extracting IOCs. No valid enteries were found.";
        document.getElementById("senddata").disabled = true;
        return;
    }
    //otherwise remove last \n character from accepted values
    else{
        acceptedvalues = acceptedvalues.substr(0, acceptedvalues.lastIndexOf("\n"));
    }

    // construct json body with iocs
    buildJSON(acceptedvalues, iocs);

    // validation succeeded, enable submission
    console.log("IOCs successfully extracted from input. Resulting JSON for submission: \n" + getItem("json"));
    document.getElementById("senddata").disabled = false;
    document.getElementById("output").innerHTML = "IOCs successfully extracted from input.";
    // note if limit was reached extracting IOCs
    document.getElementById("output").innerHTML = (100 == count)? "Limit reached. Only the first 100 IOCs successfully extracted from input." : "IOCs successfully extracted from input."; 
    document.getElementById("warning").innerHTML = "\n";
}

// construct the json object for submission
function buildJSON(acceptedvalues, iocs){
    // construct IOC expiration date
    var d = new Date();
    d.setDate(d.getDate() + 14);
    var datestring = d.toJSON();

    var description = ("" == getItem("description"))? "IOC submitted from Arbala Security Multitool.": getItem("description");

    var confidence = ("" == getItem("confidence"))? 50: parseInt(getItem("confidence"));

    var tlplevel = ("" == getItem("tlplevel"))? "white": getItem("tlplevel");

    // check if multiple IOCs will be submitted
    if(iocs.size > 1){
        multiple = true;
    }
    else{
        multiple = false;
    }

    // get keys for valid iocs
    var keys = acceptedvalues.split("\n");

    // construct JSON body for API request
    var json = (multiple)? "{\"value\": [" : "";

    // construct a json object for each ioc to add to the body
    for(let i = 0; i < keys.length; i++){
        var key = keys[i];
        if(iocs.has(key)){
            var domain = "";
            var ip = "";
            var filehashtype = "";
            var filehashvalue = "";

            // set categorized ioc
            if("domain" == iocs.get(key)){
                domain = key;
            }
            else if("ip" ==  iocs.get(key)){
                ip = key;
            }
            else{
                filehashvalue = key;
                if(key.length == 32){
                    filehashtype = "md5";
                }
                else{
                    filehashtype = "sha256";
                }
            }
            // construct json object
            var obj = JSON.stringify({
                "domainName": domain,
                "networkDestinationIPv4": ip,
                "fileHashType": filehashtype,
                "fileHashValue": filehashvalue,
                "action": "alert",
                "confidence": confidence,
                "description": description,
                "expirationDateTime": datestring,
                "severity": 0,
                "targetProduct": "Azure Sentinel",
                "threatType": "WatchList",
                "tlpLevel": tlplevel
            });
            if(i != keys.length - 1){
                obj += ',';
            }
            json += obj;

        }
    }
    if(multiple){
        json += ']}';
    }
    setItem("json", json);
}

// send the api request
function sendData(){
    console.log("Sending data.");
    // check that session is still active
    if(getItem("exp") <= Date.now()){
        document.getElementById("senddata").disabled = true;
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Please extract IOCs again.";
    }
    // proceed with callout
    else if("" != getItem("authtoken") && "" != getItem("json")){
       
        const xhr2 = new XMLHttpRequest();
        var url = (multiple)? "https://graph.microsoft.com/beta/security/tiIndicators/submitTiIndicators" : "https://graph.microsoft.com/beta/security/tiIndicators";
        // open request
        xhr2.open("POST", url);

        // set headers
        xhr2.setRequestHeader("Content-Type", "application/json; charset=utf-8");
        xhr2.setRequestHeader("Authorization", "Bearer "+ getItem("authtoken"));

        // send rquest with JSON payload
        xhr2.send(getItem("json"));
        console.log("Auth token: "+ getItem("authtoken") + "\nJSON Body: "+ getItem("json"));
        iocsChange();

        // handle response
        xhr2.onload = () =>{
            // handle success
            if(xhr2.readyState == 4 && (xhr2.status == 200 || xhr2.status == 201)){
                console.log("IOC successfully added to Sentinel Workspace.");
                var response = (multiple)? "IOCs submitted from Arbala Security Multitool." : "IOC submitted from Arbala Security Multitool.";
                document.getElementById("output").innerHTML = response;
                document.getElementById("warning").innerHTML = "\n";
                setItem("iocs", "");
                setItem("description", "");
                setElement("iocs", getItem("iocs"));
                setElement("description", getItem("description"));
            }
            // handle failure/partial success on multiple ioc submission
            else if(xhr2.readyState == 4 && xhr2.status == 206){
                console.log("Partial failure. \nStatus: "+ xhr2.status +" \nStatus text: "+ xhr2.statusText + "\body: " + xhr2.response);
                document.getElementById("output").innerHTML = "\n";
                document.getElementById("warning").innerHTML = "One or more of the submitted IOC requests was not accepted. Please check console logs for details.";
            }
            // handle failure
            else{
                console.log("Failure. \nStatus: "+ xhr2.status +" \nStatus text: "+ xhr2.statusText + "\body: " + xhr2.response);
                document.getElementById("output").innerHTML = "\n";
                document.getElementById("warning").innerHTML = "Request failed. Please check console logs for details.";
            }   
        
        };
    }
    // handle edge case of missing values
    else{
        document.getElementById("senddata").disabled = true;
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Send data failed. Issue with authorization or request body."; 
    }
}
