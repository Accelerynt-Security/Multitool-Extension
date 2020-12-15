"use strict";

document.getElementById("extract").addEventListener("click", extractIOCs);
document.getElementById("senddata").addEventListener("click", sendData);
document.getElementById("iocs").addEventListener("change", iocsChange);
document.getElementById("description").addEventListener("change", descriptionChange);
document.getElementById("tags").addEventListener("change", tagsChange);
document.getElementById("confidence").addEventListener("change", confidenceChange);
document.getElementById("tlplevel").addEventListener("change", tlplevelChange);

// loading setup
window.onload = function() {
    console.log("Azure Sentinel IOC Submission. Loading window and setting initial values.");
    // reset encryption key
    encryptionReset();
    // set initial values
    setItem("confidence", "50");
    setItem("tlplevel", "white");
    setElement("iocs", getItem("iocs"));
    setElement("description", getItem("description"));
    setElement("tags", getItem("tags"));
    setElement("confidence", getItem("confidence"));
    setElement("tlplevel", getItem("tlplevel"));
    document.getElementById("senddata").disabled = true;
    // check validity of configuration
    if("" == getItem("authtoken") || "" ==  getItem("tenantid") || "" == getItem("clientid") || "" == getItem("secret")){
        // attempt to reobtain auth token if credentials are saved
        if("" == getItem("authtoken") && "" !=  getItem("tenantid") && "" != getItem("clientid") && "" != getItem("secret")){
            getAuthToken("load");
        }
        else {
            document.getElementById("output").innerHTML = "\n";
            document.getElementById("warning").innerHTML = "Please check configuration before proceeding.";
            document.getElementById("extract").disabled = true;
        }
    }
    else{
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "\n";
        document.getElementById("extract").disabled = false;
    }
};

// reset json body and disable submit button; re-sanitization needed to form new json for request
function handleFieldChange(){
    resetJson();
    document.getElementById("senddata").disabled = true;
    document.getElementById("output").innerHTML = "\n";
    document.getElementById("warning").innerHTML = "\n";
}

// reset all json batches
function resetJson(){
    if(!isNaN(getItem("batches"))){
        for(let i = 1; i <= getItem("batches"); i++){
            var batchnumber = "batch" + i;
            setItem(batchnumber, "");
        }
    }
    setItem("batches", 1);
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

// tracks changes to tags field
function tagsChange(){
    setItem("tags", document.getElementById("tags").value);
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
            getAuthToken("extract");
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
    var data = getItem("iocs").split(/[ ,\n\t]+/);

    // track total valid entries in all batches for output display 
    var acceptedvalues = "";
    // track valid entries in the current batch
    var batchvalues = "";
    // track the number of batches 
    var batchcount = 1;
    // track the number of items in a batch
    var count = 0;

    // map to hold accepted iocs and their classifications
    var iocs = new Map();

    // extract and classify ioc data
    for(let i = 0; i < data.length;  i++){
        // api does not allow more than 100 IOCs submitted at one time
        if(count == 100){
            // if batch size is reached, build json batch and reset counts
            batchvalues = batchvalues.substr(0, batchvalues.lastIndexOf("\n"));
            // append batch to total for output
            acceptedvalues += batchvalues + "\n";
            // build json batch
            buildJSON(batchvalues, iocs, batchcount);
            // set up for next batch
            iocs.clear();
            batchvalues = "";
            batchcount += 1;
            count = 0;

        }
        // remove any trailing whitespace
        var entry = data[i].trim();
        // remove any trailing periods
        if(entry.lastIndexOf('.') == entry.length-1){
            entry = entry.substr(0, entry.length-1);
        }
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
                if(isvalid && !iocs.has(entry) && (entry.length == 32 || entry.length == 64)){
                    console.log("IOC: "+ entry + " classified as a filehash.");
                    batchvalues += entry + "\n";
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
                if(isvalid && !iocs.has(entry)){
                    console.log("IOC: "+ entry + " classified as an ip.");
                    batchvalues += entry + "\n";
                    count += 1;
                    iocs.set(entry, "ip");
                }
            }

            // possible domain
            else if(!entry.includes("..") && entry.split(".").length >= 2) {
                // remove special characters
                entry = entry.replace(/[\[\]]/g, "");
                // remove special strings
                entry = entry.replace(/CN=/g, "");
                // remove protocol
                if(entry.indexOf("://") != -1){
                    entry = entry.substr(entry.indexOf("://")+3, entry.length-1);
                }
                // remove subdomain
                if(entry.indexOf("www.") != -1){
                    entry = entry.substr(entry.indexOf("www.")+4, entry.length-1);
                }
                // remoce filepath
                if(entry.indexOf("/") != -1){
                    entry = entry.substr(0, entry.indexOf("/"));
                }
                // remove port number
                if(entry.indexOf(":") != -1){
                    entry = entry.substr(0, entry.indexOf(":"));
                }
                // check for valid domain
                var domaincheck = entry.split(".");
                var subdomaincount = 0;
                for(let j=0; j < domaincheck.length; j++){
                    if(0 < domaincheck[j].length){
                        subdomaincount += 1;
                    }
                }
                if(subdomaincount > 1 && !iocs.has(entry) && !entry.match(/[@#%~]/))
                {
                    console.log("IOC: "+ entry + " classified as a domain.");
                    batchvalues += entry + "\n";
                    count += 1;
                    iocs.set(entry, "domain");
                }
            }

        }    
    }

    // return if no data to proceed with
    if("" == batchvalues && 1 == batchcount)
    {
        console.log("No valid ioc enteries found.");
        document.getElementById("warning").innerHTML = "Failure extracting IOCs. No valid enteries were found.";
        document.getElementById("senddata").disabled = true;
        return;
    }
    // decrement batch count if last batch is empty
    else if("" == batchvalues && 1 != batchcount){
        batchcount -= 1;
    }
    // handle last batch if it contains data
    else if("" != batchvalues){
        batchvalues = batchvalues.substr(0, batchvalues.lastIndexOf("\n"));
        acceptedvalues += batchvalues;
        // construct json batch body with iocs
        buildJSON(batchvalues, iocs, batchcount);
    }

    setItem("batches", batchcount);

    // set field with accepted values
    setElement("iocs", acceptedvalues);
    setItem("iocs", acceptedvalues);

    // validation succeeded, enable submission
    console.log("IOCs successfully extracted from input.");
    document.getElementById("senddata").disabled = false;
    document.getElementById("output").innerHTML = "IOCs successfully extracted from input.";
    document.getElementById("warning").innerHTML = "\n";
}

// returns a json list of tags and reformats values displayed on form
function getTags(){
    var data = getItem("tags").split(/[ ,\n]+/);
    var tags = new Array();
    var output = "";
    for(let i = 0; i < data.length;  i++){
        tags.push(data[i].trim());
        output += data[i].trim();
        if(i != data.length-1){
            output += "\n";
        }
    }
    setElement("tags", output);
    setItem("tags", output);
    return tags;
}

// construct the json object for submission
function buildJSON(batchvalues, iocs, batchnumber){
    // construct IOC expiration date
    var d = new Date();
    d.setDate(d.getDate() + 14);
    var datestring = d.toJSON();

    var description = ("" == getItem("description"))? "IOC submitted from Arbala Security Multitool.": getItem("description");

    var confidence = ("" == getItem("confidence"))? 50: parseInt(getItem("confidence"));

    var tlplevel = ("" == getItem("tlplevel"))? "white": getItem("tlplevel");

    var tags = getTags();

    // check if multiple IOCs will be submitted
    if(iocs.size > 1){
        setItem("multiple" + batchnumber, true);
    }
    else{
        setItem("multiple" + batchnumber, false);
    }

    console.log("Total batches to be sent: " + getItem("batches"));
    // get keys for valid iocs
    var keys = batchvalues.split("\n");

    // construct JSON body for API request
    var json = (getItem("multiple" + batchnumber))? "{\"value\": [" : "";

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
                "tlpLevel": tlplevel,
                "tags": tags
            });
            if(i != keys.length - 1){
                obj += ',';
            }
            json += obj;

        }
    }
    if(getItem("multiple" + batchnumber)){
        json += ']}';
    }
    setItem("batch" + batchnumber, json);
    console.log("Batch Number: " + batchnumber + "\nJSON Request Body:\n" + json);
}

// send the api callout
function doCallout(batchnumber, batches){
    var batch = "batch" + batchnumber;
    const xhr = new XMLHttpRequest();
    var url = (getItem("multiple" + batchnumber))? "https://graph.microsoft.com/beta/security/tiIndicators/submitTiIndicators" : "https://graph.microsoft.com/beta/security/tiIndicators";
    // open request
    xhr.open("POST", url);

    // set headers
    xhr.setRequestHeader("Content-Type", "application/json; charset=utf-8");
    xhr.setRequestHeader("Authorization", "Bearer "+ getItem("authtoken"));

    // send rquest with JSON payload
    xhr.send(getItem(batch));
    // reset input fields on final batch
    if(batches == batchnumber){
        setItem("iocs", "");
        setItem("description", "");
        setItem("tags", "");
        setItem("confidence", "50");
        setItem("tlplevel", "white");
        setElement("iocs", getItem("iocs"));
        setElement("description", getItem("description"));
        setElement("tags", getItem("tags"));
        setElement("confidence", getItem("confidence"));
        setElement("tlplevel", getItem("tlplevel"));
        handleFieldChange();
        encryptionReset();
    }

    // handle response
    xhr.onload = () =>{
        // handle success
        if(xhr.readyState == 4 && (xhr.status == 200 || xhr.status == 201)){
            console.log("Batch number " + batchnumber + " out of  "+ batches + " --Success! ");
        }
        // handle failure/partial success
        else{
            console.log("Batch number " + batchnumber + " out of  "+ batches + " -- Partial failure. \nStatus: "+ xhr.status +" \nStatus text: "+ xhr.statusText + "\body: " + xhr.response);
            setItem("failedBatches", getItem("failedBatches") + 1);
        }
        // run complete, post output
        if(batches == batchnumber){
            if(0 ==  getItem("failedBatches")){
                document.getElementById("output").innerHTML = "IOC(s) successfully submitted from Arbala Security Multitool." ;
                document.getElementById("warning").innerHTML = "\n";
            }
            else{
                document.getElementById("output").innerHTML = "\n";
                document.getElementById("warning").innerHTML = "One or more of the submitted IOCs was not accepted. Please check console logs for details."; 
            }
        }
        
    
    };
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
    else if("" != getItem("authtoken") && "" != getItem("batch" + 1) && !isNaN(getItem("batches"))){
        var batches = getItem("batches");
        setItem("failedBatches", 0);
       for(let i = 1; i <= batches; i++)
       {
           doCallout(i, batches);
       }
    }
    // handle edge case of missing values
    else{
        document.getElementById("senddata").disabled = true;
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Send data failed. Issue with authorization or request body."; 
    }
}
