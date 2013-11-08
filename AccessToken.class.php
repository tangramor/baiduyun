<?php

/**
 * @desc 用于获取AccessToken的类, 要求PHP运行环境为5.2.0及以上
 * @package  
 * @author   wangjh@a-li.com.cn
 * @version  0.2
 */
require_once dirname ( __FILE__ ) . '/' . 'RequestCore.class.php';

/**
 * @desc AccessToken类
 */
class AccessToken {

  /**
   * 
   * @var array
   */
  private $_uri_prefixs = array ('https' => 'https://openapi.baidu.com/oauth/2.0/' );
  
  private $_client_id = '';
  private $_client_secret = '';

  /**
   * 初始化
   * @param string $client_id
   * @param string $client_secret
   */
  public function __construct($client_id, $client_secret) {
    $this->_client_id = $client_id;
    $this->_client_secret = $client_secret;
  }

  /**
   * 获得Authorization Code，这是Authorization Code方式取得Access Token的第一步
   * @param string $response_type
   * @param string $redirect_uri
   * @param string $scope
   * @param string $state
   * @param string $display
   * @param string $force_login
   * @param string $confirm_login
   * 
   * 其获取方式是通过重定向用户浏览器（或手机/桌面应用中的浏览器组件）到“https://openapi.baidu.com/oauth/2.0/authorize”地址上，并带上以下参数：
   *
   *    client_id：必须参数，注册应用时获得的API Key。
   *    response_type：必须参数，此值固定为“code”。
   *    redirect_uri：必须参数，授权后要回调的URI，即接收Authorization Code的URI。
   *        如果用户在授权过程中取消授权，会回调该URI，并在URI末尾附上error=access_denied参数。
   *        对于无Web Server的应用，其值可以是“oob”，此时用户同意授权后，授权服务会将
   *        Authorization Code直接显示在响应页面的页面中及页面title中。非“oob”值的
   *        redirect_uri按照如下规则进行匹配：
   *        （1）如果开发者在“授权安全设置”中配置了“授权回调地址”，则redirect_uri必须与“授权回调地址”中的某一个相匹配；
   *        （2）如果未配置“授权回调地址”，redirect_uri所在域名必须与开发者注册应用时所提供的网站根域名列表或应用的站点地址（如果根域名列表没填写）的域名相匹配。 
   *    scope：非必须参数，以空格分隔的权限列表，若不传递此参数，代表请求用户的默认权限。关于权限的具体信息请参考“权限列表”。
   *    state：非必须参数，用于保持请求和回调的状态，授权服务器在回调时（重定向用户浏览器到
   *        “redirect_uri”时），会在Query Parameter中原样回传该参数。OAuth2.0标准协议建议，利用state参数来防止CSRF攻击。。
   *    display：非必须参数，登录和授权页面的展现样式，默认为“page”，具体参数定义请参考“自定义授权页面”一节。
   *    force_login：非必须参数，如传递“force_login=1”，则加载登录页时强制用户输入用户名和口令，不会从cookie中读取百度用户的登陆状态。
   *    confirm_login：非必须参数，如传递“confirm_login=1”且百度用户已处于登陆状态，会提示是否使用已当前登陆用户对应用授权。 
   * 
   *    例如：“client_id”为“Va5yQRHlA4Fq4eR3LT0vuXV4”的应用要请求某个用户的默认权限和email访问权限，
   *      并在授权后需跳转到“http://www.example.com/oauth_redirect”，同时希望在弹出窗口中展现
   *      用户登录、授权界面，则应用需要重定向用户的浏览器到如下URL：
   *
   *    https://openapi.baidu.com/oauth/2.0/authorize?
   *      response_type=code&
   *      client_id=Va5yQRHlA4Fq4eR3LT0vuXV4&
   *      redirect_uri=http%3A%2F%2Fwww.example.com%2Foauth_redirect&
   *      scope=email&
   *      display=popup
   * 
   *  响应数据包格式
   * 
   *    此时授权服务会根据应用传递参数的不同，为用户展现不同的授权页面。如果用户在此页面同意授权，
   *      授权服务则将重定向用户浏览器到应用所指定的“redirect_uri”，并附带上表示授权服务所分配的
   *      Authorization Code的code参数，以及state参数（如果请求authorization code时带了这个参数）。
   * 
   *    例如：继续上面的例子，假设授权服务在用户同意授权后生成的Authorization Code为
   *      “ANXxSNjwQDugOnqeikRMu2bKaXCdlLxn”，则授权服务将会返回如下响应包以重定向用户浏览器到
   *      “http://www.example.com/oauth_redirect”地址上：
   * 
   *    HTTP/1.1 302 Found
   *    Location: http://www.example.com/oauth_redirect?code=ANXxSNjwQDugOnqeikRMu2bKaXCdlLxn
   *    
   *            “code”参数可以在“redirect_uri”对应的应用后端程序中获取。
   *    注意:
   *    
   *    每一个Authorization Code的有效期为10分钟，并且只能使用一次，再次使用将无效。
   * 
   * 
   */
  public function getAuthorizationCode($response_type = 'code', $redirect_uri = null, $scope = 'netdisk', $state = null, $display = 'page', $force_login = null, $confirm_login = null) { 
    $params = array(
      'client_id' => $this->_client_id,
      'response_type' => $response_type,
      'redirect_uri' => $redirect_uri == null ? 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'] : $redirect_uri,
      'scope' => $scope == null ? '' : $scope,
      'state' => $state == null ? '' : $state,
      'display' => $display == null ? '' : $display,
      'force_login' => $force_login == null ? '' : $force_login,
      'confirm_login' => $confirm_login == null ? '' : $confirm_login
      );
      
    if (is_array ( $params )) {
      $params = http_build_query ( $params, '', '&' );
    }
    
    $url = $this->_uri_prefixs ['https'] . 'authorize' . '?' . $params;

    http_redirect($url);
  }

  /**
   * 获取accessToken
   * @param string $code
   * @param string $redirect_uri
   * @return array
   * 
   *  通过上面第一步获得Authorization Code后，便可以用其换取一个Access Token。获取方式是，应用在其服务端程序中发送请求（推荐使用POST）到 百度OAuth2.0授权服务的“https://openapi.baidu.com/oauth/2.0/token”地址上，并带上以下5个必须参数：
   *
   *    grant_type：必须参数，此值固定为“authorization_code”；
   *    code：必须参数，通过上面第一步所获得的Authorization Code；
   *    client_id：必须参数，应用的API Key；
   *    client_secret：必须参数，'应用的Secret Key；
   *    redirect_uri：必须参数，该值必须与获取Authorization Code时传递的“redirect_uri”保持一致。 
   *
   *    例如：
   *    https://openapi.baidu.com/oauth/2.0/token?
   *      grant_type=authorization_code&
   *      code=ANXxSNjwQDugOnqeikRMu2bKaXCdlLxn&
   *      client_id=Va5yQRHlA4Fq4eR3LT0vuXV4&
   *      client_secret=0rDSjzQ20XUj5itV7WRtznPQSzr5pVw2&
   *      redirect_uri=http%3A%2F%2Fwww.example.com%2Foauth_redirect
   * 
   *  响应数据包格式
   * 
   *    若参数无误，服务器将返回一段JSON文本，包含以下参数：
   * 
   *    access_token：要获取的Access Token；
   *    expires_in：Access Token的有效期，以秒为单位；请参考“Access Token生命周期”
   *    refresh_token：用于刷新Access Token 的 Refresh Token,所有应用都会返回该参数；（10年的有效期）
   *    scope：Access Token最终的访问范围，即用户实际授予的权限列表（用户在授权页面时，有可能会取消掉某些请求的权限），关于权限的具体信息参考“权限列表”一节；
   *    session_key：基于http调用Open API时所需要的Session Key，其有效期与Access Token一致；
   *    session_secret：基于http调用Open API时计算参数签名用的签名密钥。 
   * 
   *    例如：
   * 
   *    HTTP/1.1 200 OK
   *    Content-Type: application/json
   *    Cache-Control: no-store
   *     
   *    {
   *        "access_token": "1.a6b7dbd428f731035f771b8d15063f61.86400.1292922000-2346678-124328",
   *        "expires_in": 86400,
   *        "refresh_token": "2.385d55f8615fdfd9edb7c4b5ebdc3e39.604800.1293440400-2346678-124328",
   *        "scope": "basic email",
   *        "session_key": "ANXxSNjwQDugf8615OnqeikRMu2bKaXCdlLxn",
   *        "session_secret": "248APxvxjCZ0VEC43EYrvxqaK4oZExMB",
   *    }
   *    
   *    若请求错误，服务器将返回一段JSON文本，包含以下参数：
   * 
   *    error：错误码；关于错误码的详细信息请参考“百度OAuth2.0错误响应”。
   *    error_description：错误描述信息，用来帮助理解和解决发生的错误。
   * 
   *    例如：
   *    
   *    HTTP/1.1 400 Bad Request
   *    Content-Type: application/json
   *    Cache-Control: no-store
   *     
   *    {
   *        "error": "invalid_grant",
   *        "error_description": "Invalid authorization code: ANXxSNjwQDugOnqeikRMu2bKaXCdlLxn"
   *    }
   */
  public function fetchAccessToken($code, $redirect_uri = null) {
    $params = array(
      'client_id' => $this->_client_id,
      'client_secret' => $this->_client_secret,
      'redirect_uri' => $redirect_uri == null ? 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'] : $redirect_uri,
      'grant_type' => 'authorization_code',
      'code' => $code
      );
      
    if (is_array ( $params )) {
      $params = http_build_query ( $params, '', '&' );
    }
    
    $url = $this->_uri_prefixs ['https'] . 'token' . '?' . $params;

    $req = new RequestCore($url);
    $req ->set_method ( 'GET' );
    $req->send_request(TRUE);
    
    $resp = json_decode($req->get_response_body());

    return $resp; //->{'access_token'};
  }
  
  /**
   * 刷新accessToken
   * @param string $refresh_token
   * @return array
   * 
   *  请求数据包格式
   *    使用Refresh Token刷新以获得新的Access Token，需要应用在其服务端发送请求（推荐用POST方法）到百度OAuth2.0授权服务的“https://openapi.baidu.com/oauth/2.0/token”地址上，并带上以下参数：
   * 
   *    grant_type：必须参数，固定为“refresh_token”；
   *    refresh_token：必须参数，用于刷新Access Token用的Refresh Token；
   *    client_id：必须参数，应用的API Key；
   *    client_secret：必须参数，应用的Secret Key;
   *    scope：非必须参数。以空格分隔的权限列表，若不传递此参数，代表请求的数据访问
   *      操作权限与上次获取Access Token时一致。通过Refresh Token刷新Access Token
   *      时所要求的scope权限范围必须小于等于上次获取Access Token时授予的权限范围。关于权限的具体信息请参考“权限列表”。 
   * 
   *    例如：
   * 
   *    https://openapi.baidu.com/oauth/2.0/token?
   *        grant_type=refresh_token&
   *        refresh_token=2.e8b7dbabc28f731035f771b8d15063f23.5184000.1292922000-2346678-124328&
   *        client_id=Va5yQRHlA4Fq4eR3LT0vuXV4&
   *        client_secret= 0rDSjzQ20XUj5itV7WRtznPQSzr5pVw2&
   *        scope=email
   * 
   * 
   *  响应数据包格式
   *    若参数无误，服务器将返回一段JSON文本，包含以下参数：
   *    access_token：要获取的Access Token；
   *    expires_in：Access Token的有效期，以秒为单位；请参考“Access Token生命周期”
   *    refresh_token：用于刷新Access Token 的 Refresh Token,并不是所有应用都会返回该参数；（10年的有效期）
   *    scope：Access Token最终的访问范围，即用户实际授予的权限列表（用户在授权页面时，有可能会取消掉某些请求的权限），关于权限的具体信息参考“权限列表”；
   *    session_key：基于http调用Open API时所需要的Session Key，其有效期与Access Token一致；
   *    session_secret：基于http调用Open API时计算参数签名用的签名密钥。 
   * 
   *    例如：
   *    HTTP/1.1 200 OK
   *    Content-Type: application/json
   *    Cache-Control: no-store
   *     
   *    {
   *        "access_token": "1.a6b7dbd428f731035f771b8d15063f61.86400.1292922000-2346678-124328",
   *        "expires_in": 86400,
   *        "refresh_token": "2.af3d55f8615fdfd9edb7c4b5ebdc3e32.604800.1293440400-2346678-124328",
   *        "scope": "basic email",
   *        "session_key": "ANXxSNjwQDugf8615OnqeikRMu2bKaXCdlLxn",
   *        "session_secret": "248APxvxjCZ0VEC43EYrvxqaK4oZExMB",
   *    }
   *    
   *    若请求错误，服务器将返回一段JSON文本，包含以下参数：
   *    error：错误码；关于错误码的详细信息请参考“百度OAuth2.0错误响应”一节。
   *    error_description：错误描述信息，用来帮助理解和解决发生的错误。 
   * 
   *    例如：
   *    
   *    HTTP/1.1 400 Bad Request
   *    Content-Type: application/json
   *    Cache-Control: no-store
   *     
   *    {
   *        "error": "invalid_grant",
   *        "error_description": "Invalid authorization code: ANXxSNjwQDugOnqeikRMu2bKaXCdlLxn"
   *    }
   * 
   */
  public function refeshAccessToken($refresh_token) {
    $params = array(
      'client_id' => $this->_client_id,
      'client_secret' => $this->_client_secret,
      'refresh_token' => $refresh_token,
      'grant_type' => 'refresh_token'
      );
      
    if (is_array ( $params )) {
      $params = http_build_query ( $params, '', '&' );
    }
    
    $url = $this->_uri_prefixs ['https'] . 'token' . '?' . $params;

    $req = new RequestCore($url);
    $req ->set_method ( 'GET' );
    $req->send_request(TRUE);
    
    $resp = json_decode($req->get_response_body());

    return $resp;
  }
  
  
  
  /**
   * 返回Access Token值。将其记录于一个csv文件，如果还未过期，则从文件中读取Token值
   * 如果即将过期，则刷新Token
   */
  public function getAccessTokenForPCS($redirect_uri, $token_store = null) {
    $token_store == null ? dirname(__FILE__ ) . '/' . 'access_token.csv' : $token_store;
    
    if (file_exists($token_store) == false) {
    
      $token = $this->returnAccessTokenValueForPCS($redirect_uri);
      
      $access_token = $token->{'access_token'};
      
      $refresh_token = $token->{'refresh_token'};
      
      $tmp = explode('.', $access_token);
      $expireTimestamp = $tmp[3];
      
      $one_day_b4_expire = $expireTimestamp - 86400;
      
      $fields = array($one_day_b4_expire, $access_token, $refresh_token);
      
      $fp = fopen($token_store, 'w');
      
      if($fp != FALSE) {
        fputcsv($fp, $fields);
        fclose($fp);
      } else {
        die("写入文件失败，请检查文件夹属性！");
      }
      
      return $access_token;
      
    } else {
      
      if (($handle = fopen($token_store, "r")) != FALSE) {
        if (($data = fgetcsv($handle, 1000, ",")) != FALSE) {
          $one_day_b4_expire = $data[0];
          $access_token = $data[1];
          $refresh_token = $data[2];
          
          fclose($handle);
          
          if(strtotime("now") > $one_day_b4_expire) {

            $token = $this->refeshAccessToken($refresh_token);
            
            $access_token = $token->{'access_token'};
      
            $refresh_token = $token->{'refresh_token'};
            
            $tmp = explode('.', $access_token);
            $expireTimestamp = $tmp[3];
            
            $one_day_b4_expire = $expireTimestamp - 86400;
    
            $fields = array($one_day_b4_expire, $access_token, $refresh_token);
            
            $fp = fopen($token_store, 'w');
            fputcsv($fp, $fields);
            fclose($fp);
            
          }
          
          return $access_token;
        } else {
          fclose($handle);
        }
                
      }

    }
  }
  
  private function returnAccessTokenValueForPCS($redirect_uri) {
    if (@$_GET['code'] == null) {
        $this->getAuthorizationCode('code', $redirect_uri, 'netdisk', null, 'page', null, null);
      } else {
        $token = $this->fetchAccessToken($_GET['code'], $redirect_uri);
        
        return $token;
      }
  }
  
}
?>
