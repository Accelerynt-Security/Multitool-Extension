"use strict";

document.getElementById("validate").addEventListener("click", validateData);
document.getElementById("senddata").addEventListener("click", sendData);
document.getElementById("domainname").addEventListener("change", domainChange);
document.getElementById("description").addEventListener("change", descriptionChange);
document.getElementById("confidence").addEventListener("change", confidenceChange);
document.getElementById("tlplevel").addEventListener("change", tlplevelChange);

var multiple = false;

window.onload = function() {
    setItem("confidence", "50");
    setItem("tlplevel", "white");
    setElement("domainname", getItem("domain"));
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

function domainChange(){
    setItem("domain", document.getElementById("domainname").value);
    setItem("json", "");
    document.getElementById("senddata").disabled = true;
    document.getElementById("output").innerHTML = "\n";
    document.getElementById("warning").innerHTML = "\n";
}

function descriptionChange(){
    setItem("description", document.getElementById("description").value);
}

function confidenceChange(){
    setItem("confidence", document.getElementById("confidence").value);
}

function tlplevelChange(){
    setItem("tlplevel", document.getElementById("tlplevel").value);
}

function validateData()
{
    console.log("Validating data.");
    // check for mising configuration values
    if("" == getItem("authtoken")){
        console.log("Validation failed. Missing configuration values.");
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Authorization Error. Please check configuration values.";

        setItem("validated", "false");
        document.getElementById("senddata").disabled = true;
    }
    // check for valid data
    else if("" == getItem("domain")){
        console.log("Validation failed. Domain required.");
        document.getElementById("warning").innerHTML = "Validation failed. Domain required.";
        
        setItem("validated", "false");
        document.getElementById("senddata").disabled = true;
    }
    else{
        // get new auth token if expired
        if(getItem("exp") <= Date.now()){
            console.log("Validating data- Auth token has expired. Requesting a new one.");
            getAuthToken(false);
        }
        else{
            buildJSON();
        }  
    }
}

function buildJSON()
{
    console.log("Constructing JSON.");

    // construct IOC expiration date
    var d = new Date();
    d.setDate(d.getDate() + 14);
    var datestring = d.toJSON();

    var description = ("" == getItem("description"))? "IOC submitted from Arbala Security Multitool.": getItem("description");

    var confidence = ("" == getItem("confidence"))? 50: parseInt(getItem("confidence"));

    var tlplevel = ("" == getItem("tlplevel"))? "white": getItem("tlplevel");

    // domain parsing
    var domains = getItem("domain").split("\n");
    if(domains.length > 1){
        multiple = true;
    }
    var json = (multiple)? "{\"value\": [" : '';
    for(let i = 0; i < domains.length;  i++){
        json += JSON.stringify({
            "DomainName": domains[i],
            "action": "alert",
            "confidence": confidence,
            "description": description,
            "expirationDateTime": datestring,
            "severity": 0,
            "targetProduct": "Azure Sentinel",
            "threatType": "WatchList",
            "tlpLevel": tlplevel
       });
       if(i != domains.length - 1)
       {
            json += ',';
       }
    }
    if(multiple){
        json += ']}';
    }
    console.log(json);
    setItem("json", json);
    document.getElementById("senddata").disabled = false;
    document.getElementById("output").innerHTML = "Validation succeeded.";
    document.getElementById("warning").innerHTML = "\n";
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
        domainChange();

        // handle response
        xhr2.onload = () =>{
            if(xhr2.readyState == 4 && (xhr2.status == 200 || xhr2.status == 201)){
                console.log("IOC successfully added to Sentinel Workspace.");
                var response = (multiple)? "IOCs submitted from Arbala Security Multitool." : "IOC submitted from Arbala Security Multitool.";
                document.getElementById("output").innerHTML = response;
                document.getElementById("warning").innerHTML = "\n";
                setItem("domain", "");
                setItem("description", "");
                setElement("domainname", getItem("domain"));
                setElement("description", getItem("description"));
            }
            else{
                console.log("Failure \nReady State: " + xhr2.readyState + " \nStatus: "+ xhr2.status +" \nStatus text: "+ xhr2.statusText + "\nHeaders: " + xhr2.getAllResponseHeaders());
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
