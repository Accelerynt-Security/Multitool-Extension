"use strict";

document.getElementById("validate").addEventListener("click", validateData);
document.getElementById("senddata").addEventListener("click", sendData);
document.getElementById("iocs").addEventListener("change", iocsChange);
document.getElementById("description").addEventListener("change", descriptionChange);
document.getElementById("confidence").addEventListener("change", confidenceChange);
document.getElementById("tlplevel").addEventListener("change", tlplevelChange);

// tracks multiple ioc submission
var multiple = false;

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
        document.getElementById("validate").disabled = true;
    }
    else{
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "\n";
        document.getElementById("validate").disabled = false;
    }
};

// tracks changes to ioc field
function iocsChange(){
    setItem("iocs", document.getElementById("iocs").value);
    setItem("json", "");
    document.getElementById("senddata").disabled = true;
    document.getElementById("output").innerHTML = "\n";
    document.getElementById("warning").innerHTML = "\n";
}

// tracks changes to description field
function descriptionChange(){
    setItem("description", document.getElementById("description").value);
}

// tracks changes to confidence field
function confidenceChange(){
    setItem("confidence", document.getElementById("confidence").value);
}

// tracks changes to tlplevel field
function tlplevelChange(){
    setItem("tlplevel", document.getElementById("tlplevel").value);
}

// initial checks before data is parsed and packaged into json
function validateData()
{
    console.log("Validating data. Running initial checks.");
    // mising configuration values
    if("" == getItem("authtoken")){
        console.log("Validation failed. Missing configuration values.");
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Authorization Error. Please check configuration values.";

        setItem("validated", "false");
        document.getElementById("senddata").disabled = true;
    }
    // missing ioc data
    else if("" == getItem("iocs")){
        console.log("Validation failed. iocs required.");
        document.getElementById("warning").innerHTML = "Validation failed. iocs required.";
        
        setItem("validated", "false");
        document.getElementById("senddata").disabled = true;
    }
    // proceed with data parsing
    else{
        // get new auth token if expired
        if(getItem("exp") <= Date.now()){
            console.log("Auth token has expired. Requesting a new one before proceeding.");
            // getAuthToken will call parseIOCs() if/when a valid token is obtained
            getAuthToken(false);
        }
        else{
            parseIOCs();
        }  
    }
}

// ioc classification and validation
function parseIOCs()
{
    console.log("Validating data. Classifying and vlaidating iocs.");
    // initial data parsing
    var data = getItem("iocs").split(/[ ,\n]+/);
    let iocs = new Array(); 
    for(let i = 0; i < data.length;  i++){
        var entry = data[i].trim();
        if(entry.length > 2){
            iocs.push(entry);
        } 
    }

    // return if no data to proceed with
    if(0 == iocs.length)
    {
        console.log("No valid ioc enteries found.");
        document.getElementById("warning").innerHTML = "Validation failed. No valid ioc enteries found.";
        setItem("validated", "false");
        document.getElementById("senddata").disabled = true;
        return;
    }

    // check if multiple IOCs will be submitted
    if(iocs.length > 1){
        multiple = true;
    }
    else{
        multiple = false;
    }

    // construct JSON body for API request
    var json = (multiple)? "{\"value\": [" : '';

    // ioc classification & validation
    for(let i = 0; i < iocs.length;  i++){
        var ioc = iocs[i];
        var domain = "";
        var ip = "";
        var filehashtype = "";
        var filehashvalue = "";
        var comma = Boolean(i != iocs.length - 1);

        // file hash
        if(!ioc.includes(".")){
            console.log("IOC: "+ ioc + " classified as a file hash.");
            console.log("Setting "+ filehashtype + " as the file hash type.");
            filehashvalue = ioc;
            filehashtype = "sha256";
        }
        // ip
        else if(!ioc.match(/[A-Za-z]/)){
            console.log("IOC: "+ ioc + " classified as an ip.");
            // check for valid ip range
            var ipCheck = ioc.split(".");
            for(let j=0; j < ipCheck.length; j++){
                var number = parseInt(ipCheck[j]);
                if(ipCheck.length != 4 || isNaN(number) || number < 0 ||  number > 255){
                    console.log("Invalid bit length or IP range for "+ ioc);
                    document.getElementById("warning").innerHTML = "Validation failed. Invalid IP.\n " + ioc;
                    setItem("validated", "false");
                    document.getElementById("senddata").disabled = true;
                    return;
                }
            }
            ip = ioc;
        }
        // domain
        else{
            console.log("IOC: "+ ioc + " classified as a domain.");
            domain = ioc;
        }
        json += buildJSON(domain, ip, filehashtype, filehashvalue, comma);
    }
    if(multiple){
        json += ']}';
    }
    console.log("Validation succeeded. Resulting JSON for submission: \n" + json);
    setItem("json", json);
    document.getElementById("senddata").disabled = false;
    document.getElementById("output").innerHTML = "Validation succeeded.";
    document.getElementById("warning").innerHTML = "\n";
}

function buildJSON(domain, ip, filehashtype, filehashvalue, comma){
    // construct IOC expiration date
    var d = new Date();
    d.setDate(d.getDate() + 14);
    var datestring = d.toJSON();

    var description = ("" == getItem("description"))? "IOC submitted from Arbala Security Multitool.": getItem("description");

    var confidence = ("" == getItem("confidence"))? 50: parseInt(getItem("confidence"));

    var tlplevel = ("" == getItem("tlplevel"))? "white": getItem("tlplevel");
    
    // construct JSON object
    var json = JSON.stringify({
        "DomainName": domain,
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
   if(comma)
    {
        json += ',';
    }
   return json;
}

function sendData(){
    console.log("Sending data.");
    // check that session is still active
    if(getItem("exp") <= Date.now()){
        document.getElementById("senddata").disabled = true;
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Please revalidate.";
    }
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
            else if(xhr2.readyState == 4 && xhr2.status == 206){
                console.log("Partial failure. \nStatus: "+ xhr2.status +" \nStatus text: "+ xhr2.statusText + "\body: " + xhr2.response);
                document.getElementById("output").innerHTML = "\n";
                document.getElementById("warning").innerHTML = "One or more of the submitted IOC requests was not accepted. Please check console logs for details.";
            }
            else{
                console.log("Failure. \nStatus: "+ xhr2.status +" \nStatus text: "+ xhr2.statusText + "\body: " + xhr2.response);
                document.getElementById("output").innerHTML = "\n";
                document.getElementById("warning").innerHTML = "Request failed. Please check console logs for details.";
            }   
        
        };
    }
    else{
        document.getElementById("senddata").disabled = true;
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Send data failed. Issue with authorization or request body."; 
    }
}
