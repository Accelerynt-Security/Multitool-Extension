
"use strict";

document.getElementById("setconfig").addEventListener("click", setConfig);
document.getElementById("tenantid").addEventListener("change", configChange);
document.getElementById("clientid").addEventListener("change", configChange);
document.getElementById("secret").addEventListener("change", configChange);
document.getElementById("ioc").addEventListener("click", loadIOC);

window.onload = function() {
    if(getItem("authtoken").length > 0){
        document.getElementById("setconfig").disabled = true;
    }
    else{
        document.getElementById("ioc").disabled = true;
    }
    setElement("tenantid",  "*".repeat(getItem("tenantid").length));
    setElement("clientid",  "*".repeat(getItem("clientid").length));
    setElement("secret", "*".repeat(getItem("secret").length));
    document.getElementById("output").innerHTML = "\n";
    document.getElementById("warning").innerHTML = "\n";
};

function configChange(){
    document.getElementById("setconfig").disabled = false;
    document.getElementById("output").innerHTML = "\n";
    document.getElementById("warning").innerHTML = "\n";
}

function setConfig(){
    // grab config values
    setItem("key", generateKey());
    setItem("tenantid",  document.getElementById("tenantid").value);
    setItem("clientid", document.getElementById("clientid").value);
    setItem("secret", document.getElementById("secret").value);

    if("" !=  getItem("tenantid")  && "" != getItem("clientid") && "" != getItem("secret"))
    {
        setElement("tenantid",  "*".repeat(getItem("tenantid").length));
        setElement("clientid",  "*".repeat(getItem("clientid").length));
        setElement("secret", "*".repeat(getItem("secret").length));
        
        getAuthToken("config");
        document.getElementById("setconfig").disabled = true;
    }
    else{
        console.log("Missing configuration values.");
        document.getElementById("output").innerHTML = "\n";
        document.getElementById("warning").innerHTML = "Missing configuration values.";
    }
}
function loadIOC(){
    window.open("ioc.html");
}
