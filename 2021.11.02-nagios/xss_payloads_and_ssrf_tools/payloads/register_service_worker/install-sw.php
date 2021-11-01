<?php
if ($_GET['sw'] == "true") {
  header('Service-Worker-Allowed: /');
  header('Content-Type: application/javascript');
?>
// contents of sw.js
%%SW_CONTENTS%%
<?php } else { ?>
<script>
  window.onload = function() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/nagiosxi/includes/components/highcharts/exporting-server/temp/install-sw.php?sw=true', { scope: '/' })
      .then(function(registration) {
        console.debug('Registration successful, scope is:', registration.scope);
      })
      .catch(function(error) {
        console.debug('Service worker registration failed, error:', error);
      });
    }
  };
</script>
<?php } ?>
