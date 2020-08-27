"use strict";

document.getElementById("config").addEventListener("click", loadConfig);
document.getElementById("ioc").addEventListener("click", loadIOC);

function loadConfig(){
    window.open("configuration.html");
}

function loadIOC(){
    window.open("ioc.html");
}