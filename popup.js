//
function getURL() {
browser.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    var url = tabs[0].url;
    document.getElementById("url").textContent = url;
    document.getElementById("url").style.color = "#2f3330";
  });
}
document.getElementById("checkBTN").addEventListener("click",getURL);