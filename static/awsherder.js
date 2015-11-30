function redirect() {
  var redirect_millis = 5000;
  window.setTimeout(function(){
    var redirect_url = $('#redirect_url').data();
    console.info('Redirect to ' + redirect_url + ' in ' + redirect_millis + ' milliseconds')
    window.location.replace(redirect_url);
  }, redirect_millis );
}
