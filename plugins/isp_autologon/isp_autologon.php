<?php

/** 
 * @license GNU GPLv3+
 * @author Nikita Lipchik
 */
class isp_autologon extends rcube_plugin
{
  public $task = 'login';

  function init()
  {
    $this->add_hook('startup', array($this, 'startup'));
    $this->add_hook('authenticate', array($this, 'authenticate'));
  }

  function startup($args)
  {
    // change action to login
    if (empty($_SESSION['user_id']) && !empty($_GET['tkn']))
      $args['action'] = 'login';
    
    return $args;
  }

  function authenticate($args)
  {
    $salt = $this->app->config->get('isp_salt');
    $mail_domain = $this->app->config->get('isp_mail_domain');
    $isp_login = $this->app->config->get('isp_login');
    $isp_password = $this->app->config->get('isp_password');
    $isp_host = $this->app->config->get('isp_host');
    $user = filter_input(INPUT_GET, 'user', FILTER_SANITIZE_STRING);
    $time = filter_input(INPUT_GET, 'time', FILTER_SANITIZE_STRING);
    $tkn = filter_input(INPUT_GET, 'tkn', FILTER_SANITIZE_STRING);
    $time_now = time();
    $time_delta = $time_now - $time;
    $mailbox_name = $user."@".$mail_domain;
    $isp_auth = $this->isp_get_auth($isp_login, $isp_password, $isp_host);
    $mailbox = $this->isp_get_mailbox($mailbox_name, $isp_auth, $isp_host);
    if (empty($mailbox->elid[0])){
        $this->isp_create_mailbox($isp_host, $user, $isp_auth);
        $mailbox = $this->isp_get_mailbox($mailbox_name, $isp_auth, $isp_host);
    }
    if (!empty($mailbox->elid[0])){
        $check_tkn =  md5($time . $user . $salt);
        if($check_tkn === $tkn && $time_delta < 7){
            $args['user'] = strval($mailbox->elid[0]);
            $args['pass'] = strval($mailbox->passwd[0]);
            $args['host'] = 'localhost';
            $args['cookiecheck'] = false;
            $args['valid'] = true;
        }
    }
    return $args;
  }
  
  
  function isp_get_mailbox($name_mailbox, $auth, $host)
  {
    //Получить данные почтового ящика.
    $result = "";
    $request="https://".$host."/ispmgr?out=xml&auth=".$auth."&func=email.edit&elid=".$name_mailbox;
    $fh = fopen($request, "r");
    while( $data = fread( $fh, 4096 ) ){
        $result .= $data;
    }
    fclose( $fh );
    $ansver_xml = simplexml_load_string($result);
    return $ansver_xml;
  }
  function isp_create_mailbox($host ,$name, $auth)
  {
      //Создать почтовый ящик
          $result = "";
    $request="https://".$host."/ispmgr?out=xml&auth=".$auth."&func=email.edit&sok=yes&name=".$name."&passwd=".$this->generatePassword();
    //echo $request;
    $fh = fopen($request, "r");
    while( $data = fread( $fh, 4096 ) ){
        $result .= $data;
    }
    fclose( $fh );
    $ansver_xml = simplexml_load_string($result);
    return $ansver_xml;
  }
function isp_get_auth($login, $password, $host)
  {
    //Получить токен авторизации для работы с ISPmanager
    $result = "";
    $request="https://".$host."/ispmgr?out=xml&func=auth&authinfo=".$login.":".$password;
    $fh = fopen($request, "r");
    while( $data = fread( $fh, 4096 ) ){
        $result .= $data;
    }
   fclose( $fh );
   $ansver_xml = simplexml_load_string($result);
   return $ansver_xml->auth[0];   
  }
function generatePassword($length = 8) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $count = mb_strlen($chars);
    for ($i = 0, $result = ''; $i < $length; $i++) {
        $index = rand(0, $count - 1);
        $result .= mb_substr($chars, $index, 1);
    }
    return $result;
}
}

