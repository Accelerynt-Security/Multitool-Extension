"use strict";

document.getElementById("setconfig").addEventListener("click", setConfig);
document.getElementById("tenantid").addEventListener("change", configChange);
document.getElementById("clientid").addEventListener("change", configChange);
document.getElementById("secret").addEventListener("change", configChange);

window.onload = function() {
    setElement("tenantid",  getItem("tenantid"));
    setElement("clientid", getItem("clientid"));
    setElement("secret", getItem("secret"));
    document.getElementById("output").innerHTML = "\n";
    document.getElementById("warning").innerHTML = "\n";
};

function configChange(){
    document.getElementById("output").innerHTML = "\n";
    document.getElementById("warning").innerHTML = "\n";
}

function setConfig(){
    // grab config values
    setItem("tenantid",  document.getElementById("tenantid").value);
    setItem("clientid", document.getElementById("clientid").value);
    setItem("secret", document.getElementById("secret").value);

    if("" !=  getItem("tenantid")  && "" != getItem("clientid") && "" != getItem("secret"))
    {
        setElement("tenantid",  getItem("tenantid"));
        setElement("clientid",  getItem("clientid"));
        setElement("secret", getItem("secret"));
        
        getAuthToken(true);
    }
    else{
        console.log("Missing configuration values.");
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Missing configuration values.";
    }
}