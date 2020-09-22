<?php

  // ? AWS Cognito SDK Wrapper

  use Aws\CognitoIdentity\CognitoIdentityClient;
  use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;


  class CognitoAuth{

    private $client = null;
    public $user = false;

    // ? AWS Cognito Config
    private $POOL_ID;
    private $REGION;
    private $APP_CLIENT_ID;
    private $AWS_ACCESS_KEY;
    private $AWS_ACCESS_SECRET_KEY;
    private $AUTH_FLOW;
    private static $TIME_OUT = 60; // minutes to session timeout

    // ? Hosted login page & AWS API Endpoints
    public $AWS_DOMAIN;
    public $AWS_LOGIN_REDIRECT_URI;
    public $AWS_ENDPOINT_HOSTED_LOGIN;
    private $AWS_ENDPOINT_TOKEN;

    function __construct(array $pool_config, bool $login=false){

      // ? Cognito Config
      $this->POOL_ID = $pool_config['POOL_ID'];
      $this->REGION = $pool_config['REGION'];
      $this->APP_CLIENT_ID = $pool_config['APP_CLIENT_ID'];
      $this->AWS_ACCESS_KEY = $pool_config['AWS_ACCESS_KEY'];
      $this->AWS_ACCESS_SECRET_KEY = $pool_config['AWS_ACCESS_SECRET_KEY'];
      $this->AWS_DOMAIN = $pool_config['DOMAIN'];
      $this->AWS_LOGIN_REDIRECT_URI = $pool_config['LOGIN_REDIRECT_URI'];
      $this->AUTH_FLOW = 'ADMIN_NO_SRP_AUTH';

      // ? Cognito API Endpoints
      $this->AWS_ENDPOINT_HOSTED_LOGIN = $pool_config['HOSTED_LOGIN_URI'];
      $this->AWS_ENDPOINT_TOKEN = $this->AWS_DOMAIN . "/oauth2/token";

      // ? Setup args for CognitoIdentityProviderClient Class
      $args = [
        'credentials' => [
            'key' => $this->AWS_ACCESS_KEY,
            'secret' => $this->AWS_ACCESS_SECRET_KEY,
        ],
        'region' => $this->REGION,
        'version' => 'latest',

        'app_client_id' => $this->APP_CLIENT_ID,
        // 'app_client_secret' => '',
        'user_pool_id' => $this->POOL_ID,
      ];

      $this->client = new CognitoIdentityProviderClient($args);

      if($login){
        $this->Login_User();
      }

    }

    // *************************************************
    // ******** REFACTOR OR REMOVE METHODS *************
    // *************************************************

    // ? CREATE_USER - Used for regular signups, without a temppass
    // ? @param $username <string>
    // ? @param $email <string>
    // ? @param $password <string>
    // ? @return <bool> success
    // TODO Not needed now?
    public function Create_User(string $username, string $password, array $attributes){

      $email = $attributes[0]['Value'];

      try{
        $result = $this->client->signUp([
          'ClientId' => $this->APP_CLIENT_ID,
          'Username' => $username,
          'Password' => $password,
          'UserAttributes' => $attributes,
          'ValidationData' => [
          [
            'Name' => 'email',
            'Value' => $email
          ],
          ],
        ]);
        return true;
      } catch (\Exception $e) {
        error_log("Cognito.class.php->Create_User Error: " . $e->getMessage());
      }

      // ? Results look like below
      // [
      //  'CodeDeliveryDetails' => [
      //    'AttributeName' => '<string>',
      //    'DeliveryMedium' => 'SMS|EMAIL',
      //    'Destination' => '<string>',
      //  ],
      //  'UserConfirmed' => true || false,
      //  'UserSub' => '<string>',
      // ]

      return false;

    }

    // TODO not needed?
    public function Change_Password(string $current_password, string $new_password){

      if($this->user){
        try{
          $result = $this->client->changePassword([
            'AccessToken' => $this->user["AccessToken"],
            'PreviousPassword' => $current_password,
            'ProposedPassword' => $new_password
          ]);
          return true;
        } catch(\Exception $e){
          error_log($e->getMessage());
        }
        return false;
      }
    }

    // TODO not needed?
    public function Toggle_Mfa(string $email){

      $state = $this->Admin_Set_Mfa_Status($email);
      $state = !$state;

      try{
        $result = $this->client->adminSetUserMFAPreference([
          'SMSMfaSettings' => [
            'Enabled' => $state,
            'PreferredMfa' => $state
          ],
          // 'SoftwareTokenMfaSettings' => [
          //   'Enabled' => true,
          //   'PreferredMfa' => true,
          // ],
          'UserPoolId' => $this->POOL_ID,
          'Username' => $this->user["Username"],
        ]);

        // ! DEBUG
        // $this->pprint($result);

        // ? Update Session and Obj Settings
        $_SESSION["User"]["MfaEnabled"] = $state;
        $this->user["MfaEnabled"] = $state;

        // return $state;
        return ($state ? "Enabled" : "Disabled");

      } catch(\Exception $e){
        error_log($e->getMessage());
        return null;
      }

      return false;
    }

    public function Admin_Set_Mfa_Status($email){

      global $COGNITO_CONFIG;


	    try{
			  $userpool = new CognitoAuth($COGNITO_CONFIG, true);
				$info = $userpool->Admin_Get_User($email);

				if (isset($info['MfaSMSEnabled'])) {
					$state = $info['MfaSMSEnabled'];
				}
				else {
					$state = 0;
				}

		    $_SESSION["User"]["MfaEnabled"] = $state;
		    $this->user["MfaEnabled"] = $state;

		    return $state;
	      } catch(\Exception $e){
	        error_log($e->getMessage());
	        return null;
	      }
	    }

    // *************************************************
    // *********** USER ACCOUNT METHODS ****************
    // *************************************************


    public function Admin_Get_User(string $username){

      try{
        $aws_result_obj = $this->client->adminGetUser([
          'Username' =>  $username,
          'UserPoolId' => $this->POOL_ID,
        ]);
        return $this->Extract_User_Info($aws_result_obj);
      } catch(\Exception $e){
        #error_log($e->getMessage());
        return false;
      }
    }

    public function Admin_Get_User_By_Sub(string $sub){
      try{
      	$sub_filter = 'sub = "'. $sub .'"';
        $aws_result_obj = $this->client->listUsers([
          "Filter" => $sub_filter,
          'Limit' => 1,
          'UserPoolId' => $this->POOL_ID,
        ]);
    		//return $aws_result_obj;
        return $this->Extract_User_Info($aws_result_obj['Users'][0]);
      } catch(\Exception $e){
        #error_log($e->getMessage());
        return false;
      }
    }

    // ? ADMIN_CREATE_USER - Used to create accounts with temporary passwords
    public function Admin_Create_User(string $username, string $name, string $phone){

      try{
        $result = $this->client->adminCreateUser([
          'DesiredDeliveryMediums' => ['EMAIL'], // SMS || EMAIL
          'ForceAliasCreation' => false, // true || false
          'UserAttributes' => [
            [
              'Name' => 'email',
              'Value' => $username
            ],
            [
              'Name' => 'name',
              'Value' => $name
            ],
            [
              'Name' => 'phone_number',
              'Value' => $phone
            ],
            [
              'Name' => 'email_verified',       // required to send password resets
              'Value' => 'true'
            ]
          ],
          'UserPoolId' => $this->POOL_ID,
          'Username' => $username,
          'ValidationData' => [
            [
              'Name' => 'email',
              'Value' => $username
            ],
          ],
        ]);
        return $result;

      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Create_User(): Error - " . $ex->getMessage());
        return false;
      }

    }


    // ? DELETE_USER - Deletes the user from pool
    // ? @param <string> username
    // ? @return <bool> success
    public function Admin_Delete_User(string $username) : bool{
      try {
        $result = $this->client->adminDeleteUser([
          'UserPoolId' => $this->POOL_ID,
          'Username' => $username,
        ]);
        return true;
      } catch(Exception $e){
        error_log($e->getMessage());
        return false;
      }
    }

    // ? DISABLE_USER
    // ? @param $username <string>
    // ? @return <bool> success
    public function Admin_Disable_User(string $username) : bool{
      try{
        $result = $this->client->adminDisableUser([
          'UserPoolId' => $this->POOL_ID,
          'Username' => $username,
        ]);
        return true;
      } catch(Exception $e){
        error_log($e->getMessage());
        return false;
      }
    }

    // ? ENABLE_USER
    // ? @param $username <string>
    // ? @return <bool> success
    public function Admin_Enable_User(string $username) : bool{
      try{
        $result = $this->client->adminEnableUser([
          'UserPoolId' => $this->POOL_ID,
          'Username' => $username,
        ]);
        return true;
      } catch(Exception $e){
        error_log($e->getMessage());
        return false;
      }
    }

    // ? @return <bool> success
    public function Admin_Toggle_User(string $username) : bool{

      $user = $this->Admin_Get_User($username);
      if($user['Enabled']){
        $success = $this->Admin_Disable_User($username);
      } else {
        $success = $this->Admin_Enable_User($username);
      }
      return $success;
    }

    // ? ADMIN_RESET_PASSWORD - Invalidates User's password; must change next login
    // ? @return <bool> success
    public function Admin_Reset_Password(string $username) : bool{
      try {
        $this->client->adminResetUserPassword([
          'UserPoolId' => $this->POOL_ID,
          'Username' => $username
        ]);
        return true;
      } catch (\Exception $e) {
        error_log($e->getMessage());
      }
      return false;
    }

    // ? @return <bool> success
    public function Admin_Toggle_Mfa(string $username) : bool{
      try{
        $user = $this->Admin_Get_User($username);
        $state = !$user["MfaSMSEnabled"];
        if ($state) {
        	$state = true;
        }
        else {
        	$status = false;
        }

        $result = $this->client->adminSetUserMFAPreference([
          'SMSMfaSettings'=> [
            'Enabled'       => $state,
            'PreferredMfa'  => $state,
          ],
          'UserPoolId'  => $this->POOL_ID,
          'Username'    => $username
        ]);
        return true;

      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Toggle_Mfa(): Error - $ex");
        return false;
      }
    }

    public function Admin_User_Update_Attribute(string $username, string $attribute, string $value) : bool{

      try{
        $result = $this->client->adminUpdateUserAttributes([
          'UserAttributes' => [
              [
                  'Name' => $attribute,
                  'Value' => $value,
              ],
          ],
          'UserPoolId' => $this->POOL_ID,
          'Username' => $username,
        ]);
        return true;

      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_User_Update_Attribute(): Error - " . $ex->getMessage());
        return false;
      }
    }

    public function Admin_User_Add_Custom_Attribute(string $username, string $attribute, string $value) : bool{


      return false;
    }

    // *************************************************
    // *********** USER ACCOUNT METHODS ****************
    // *************************************************



    // *************************************************
    // ************** GROUP METHODS ********************
    // *************************************************
    public function Admin_Group_List(){

      try{
        $result = $this->client->listGroups([
          // 'Limit' => <integer>,
          'UserPoolId' => $this->POOL_ID
        ]);

      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Group_List(): AWS Error -" . $ex->getMessage());
        return false;
      }

      return $result["Groups"];

      // $groups = array_map(function($group){
      //   return ["Name" => $group['GroupName'], "Description" => $group['Description']];
      // }, $result['Groups']);
      // return $groups;
    }

    public function Admin_Group_Users(string $group_name){
      try{
        $result = $this->client->listUsersInGroup([
          'GroupName' => $group_name,
          // 'Limit' => <integer>,
          // 'NextToken' => '<string>',
          'UserPoolId' => $this->POOL_ID,
        ]);
      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Group_Users(): AWS Error -" . $ex->getMessage());
        return false;
      }

      return $result["Users"];

      // $users = array_map(function($user){
      //   return ["Name" => $group['GroupName'], "Description" => $group['Description']];
      // }, $result['Groups']);
      // return $users;
    }

    public function Admin_Group_List_By_User(string $sub){

      try{
        $result = $this->client->adminListGroupsForUser([
          // 'Limit' => <integer>,
          'UserPoolId' => $this->POOL_ID,
          // 'Username' => $username,
          'Username' => $sub,
        ]);
      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Group_List_By_User(): AWS Error -" . $ex->getMessage());
        return false;
      }

      return $result['Groups'];
    }

    public function Admin_Group_Create(string $name, string $description): bool{
      try{
        $result = $this->client->createGroup([
          'Description' => $description,
          'GroupName' => $name,
          // 'Precedence' => <integer>,
          // 'RoleArn' => '<string>',
          'UserPoolId' => $this->POOL_ID,
        ]);
        return true;
      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Group_Create(): AWS Error -" . $ex->getMessage());
        return false;
      }
    }

    public function Admin_Group_Delete(string $name): bool{
      try{
        $result = $this->client->deleteGroup([
          'GroupName' => $name,
          'UserPoolId' => $this->POOL_ID,
        ]);
        return true;
      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Group_Delete(): AWS Error -" . $ex->getMessage());
        return false;
      }
    }

    public function Admin_Group_Update(string $name, string $description, string $role = null, int $precedence = null): bool{
      try{
        $result = $this->client->updateGroup([
          'GroupName' => $name,
          'Description' => $description,
          // 'Precedence' => $precedence,
          // 'RoleArn' => $role,
          'UserPoolId' => $this->POOL_ID,
        ]);
        return true;
      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Group_Update(): AWS Error -" . $ex->getMessage());
        return false;
      }
    }

    public function Admin_Group_Remove_User(string $group, string $user_sub){
      try{
        $result = $this->client->adminRemoveUserFromGroup([
          'GroupName' => $group,
          'Username' => $user_sub,
          'UserPoolId' => $this->POOL_ID,
        ]);
        return true;
      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Group_Remove_User(): AWS Error -" . $ex->getMessage());
        return false;
      }
    }

    public function Admin_Group_Add_User(string $group, string $user_sub){
      try{
        $result = $this->client->adminAddUserToGroup([
          'GroupName' => $group,
          'Username' => $user_sub,
          'UserPoolId' => $this->POOL_ID,
        ]);
        return true;
      } catch(\Exception $ex){
        error_log("Cognito.class.php->Admin_Group_Add_User(): AWS Error -" . $ex->getMessage());
        return false;
      }
    }
    // *************************************************
    // ************ END GROUP METHODS ******************
    // *************************************************



    // *************************************************
    // ************** AUTH METHODS *********************
    // *************************************************

    // ? Authenticates Username/Password and returns tokens
    // ? @param $username <string>
    // ? @param $password <string>
    // ? @returns <array> Access Tokens
    private function Auth_User(string $username, string $password){

      try{

        $result = $this->client->adminInitiateAuth([
          'AuthFlow' => $this->AUTH_FLOW,
          'AuthParameters' => [
              'USERNAME' => $username,
              'PASSWORD' => $password,
              // 'SECRET_HASH' => base64_encode(hash_hmac('sha256', YOUR_USERNAME_HERE . APP_CLIENT_ID, APP_CLIENT_SECRET, true))
          ],
          'ClientId' => $this->APP_CLIENT_ID,
          'UserPoolId' => $this->POOL_ID,
        ]);

        $temp = $result->get('AuthenticationResult');
        $access_token = $result->get('AuthenticationResult')['AccessToken'];
        $refresh_token = $result->get('AuthenticationResult')['RefreshToken'];

        return $access_token;

      } catch(Exception $e){
        // ? AWS User Exception Message
        echo "Error: " . $e->getAwsErrorMessage();
      }

      // ? Results look like below
      // [
      //   'AuthenticationResult' => [
      //     'AccessToken' => '<string>',
      //     'ExpiresIn' => <integer>,
      //     'IdToken' => '<string>',
      //     'NewDeviceMetadata' => [
      //       'DeviceGroupKey' => '<string>',
      //       'DeviceKey' => '<string>',
      //     ],
      //     'RefreshToken' => '<string>',
      //     'TokenType' => '<string>',
      //   ],
      //   'ChallengeName' => 'SMS_MFA|SOFTWARE_TOKEN_MFA|SELECT_MFA_TYPE|MFA_SETUP|PASSWORD_VERIFIER|CUSTOM_CHALLENGE|DEVICE_SRP_AUTH|DEVICE_PASSWORD_VERIFIER|ADMIN_NO_SRP_AUTH|NEW_PASSWORD_REQUIRED',
      //   'ChallengeParameters' => ['<string>', ...],
      //   'Session' => '<string>',
      // ]

      return false;
    }

    // ? LOGIN_USER - Handles tokens & creates SESSION if valid
    // ? @param <array> aws access tokens
    // ? @return <bool>
    public function Login_User($tokens = false){

      $this->user = self::Session_Get() ?? false;
      $session = $this->user;

      // ? Kills session/invalidates auth tokens just incase they still exist
      if(!$session && !$tokens){
        $this->Logout();
        return false;
      }

      try{

        if($session && !$tokens){
          $tokens = [
            "access_token" => $session["AccessToken"],
            "id_token" => $session["IdToken"],
            "refresh_token" => $session["RefreshToken"]
          ];
        }

        $aws_result_obj = $this->Auth_Token($tokens["access_token"]);

        // ? Try to refresh tokens if possible
        if(!$aws_result_obj){
          $result = $this->Refresh_Tokens($tokens['refresh_token']);
          $tokens['access_token'] = $result['access_token'];
          $tokens['id_token'] = $result['id_token'];
          $aws_result_obj = $this->Auth_Token($tokens["access_token"]);
        }

        // ? Get full user info and create session
        if($aws_result_obj && $tokens){

          $user_info = $this->Admin_Get_User($aws_result_obj['Username']);

          if(!$session){
            $session = self::Session_Create($tokens, $user_info);
            $this->user = $session;
          } else {
            $_SESSION["User"]["AccessToken"] = $tokens["access_token"];
            $_SESSION["User"]["IdToken"] = $tokens["id_token"];
            // $_SESSION["User"]["TimeOut"] = time() + (60 * self::$TIME_OUT);
            // error_log("New TIMEOUT @ " . $_SESSION["User"]["TimeOut"]);
            $this->user = self::Session_Get();
          }

          return true;
        }

      } catch(\Exception $ex){
        error_log("Cognito.class.php->Login_User(): Error - $ex");
        return false;
      }

    }


    // ? @return <aws_result_object> user info from user pool
    private function Auth_Token($access_token){
      try {
        $aws_result_obj = $this->client->getUser([
            'AccessToken' => $access_token
        ]);
        return $aws_result_obj;

      } catch(\Exception  $e) {
        // TODO Show user a message maybe?
        #error_log("Cognito.class.php->Auth_Token Error: " . $e->getMessage());
      }

      return false;
    }

    // ? LOGOUT - Delete session data
    public function Logout(string $redirect_path = null){


      $session = self::Session_Get(true);
      if(!$session) return false;

      try{
        if ($this->client->AdminUserGlobalSignOut([
          "Username" => $session["Username"],
          "UserPoolId" => $this->POOL_ID,
        ])){
          self::Session_End();
        }

      } catch(\Exception $e){
        error_log("CognitoAuth->Logout(): Error - " . $e->getMessage());
      }

      if($redirect_path){
        self::Load_Page($redirect_path);
      }
    }

    // ? EXCHANGE_AUTH_CODE - Gets access tokens from AUTH CODE GRANT via cURL POST Request
    // ? @param <string> auth_code Returned from login endpoint with "code" type
    // ? @return <bool> success status
    public function Exchange_Auth_Code(string $auth_code){

      $data = "grant_type=authorization_code"
        . "&client_id=" . $this->APP_CLIENT_ID
        . "&code=" . $auth_code
        . "&redirect_uri=" . $this->AWS_LOGIN_REDIRECT_URI;

      $response = $this->Send_Post($this->AWS_ENDPOINT_TOKEN, $data);
      $error = isset($response["error"]);

      if(!$error){
        $this->Login_User($response);
        return true;
      } else {
        error_log("ERROR: Cognito.class.php->Exchange_Auth() - " . $response["error"]);
      }

      return false;
    }

    // ? Sends a request to TOKEN endpoint
    // ? @returns <bool> success
    private function Refresh_Tokens(string $refresh_token){

      $data = "grant_type=refresh_token"
      . "&client_id=" . $this->APP_CLIENT_ID
      . "&refresh_token=" . $refresh_token;

      $response = $this->Send_Post($this->AWS_ENDPOINT_TOKEN, $data);
      $error = isset($response["error"]);

      if(!$error){
        return $response;
      } else {
        error_log("ERROR: Cognito.class.php->Refresh_Tokens() - " . $response["error"]);
      }

      return false;
    }

    // ? REQUIRE_AUTH - Call on pages to require auth state
    public function Require_Auth(bool $state, $redirect = false){

      if( ($state && !$this->user) || (!$state && $this->user) ){
        self::Load_Page($redirect);
      }

    }
    // *************************************************
    // ************** END AUTH METHODS *****************
    // *************************************************



    // *************************************************
    // ************** SESSION METHODS ******************
    // *************************************************

    // ? SESSION_CREATE
    public static function Session_Create(array $tokens, $user_info){

      $session = [
        "AccessToken"   => $tokens["access_token"],
        "IdToken"       => $tokens["id_token"],
        "RefreshToken"  => $tokens['refresh_token'],

        "Username"      => $user_info['Username'],
        "Email"         => $user_info['email'],
        "Phone"         => $user_info['phone_number'],
        "Name"          => $user_info['name'],
        "Sub"           => $user_info['sub'],

        "MfaEnabled"    => $user_info['MfaSMSEnabled'],
        "Enabled"       => $user_info['Enabled'],
        "Status"        => $user_info['UserStatus'],

        "REMOTE_ADDR"   => $_SERVER['REMOTE_ADDR'],
        "HTTP_IP"       => $_SERVER['HTTP_X_FORWARDED_FOR'],
        "UserAgent"     => $_SERVER['HTTP_USER_AGENT'],
      ];

      $_SESSION["User"] = $session;
      self::Session_Update_Timeout();

      return $session;
    }

    // ? SESSION_END
    public static function Session_End(){
      $_SESSION = array();
      // session_destroy();
    }

    // ? SESSION_VALID - Does some user ip & agent checking
    public static function Session_Valid(){

      if(!isset($_SESSION["User"]['REMOTE_ADDR']) ||
        !isset($_SESSION["User"]['UserAgent']) ||
        !isset($_SESSION["User"]['TimeOut']) ||
        !isset($_SESSION["User"]['HTTP_IP'])) return false;

      $same_remote_ip = $_SESSION["User"]["REMOTE_ADDR"] == $_SERVER["REMOTE_ADDR"];
      $same_agent = $_SESSION["User"]["UserAgent"] == $_SERVER["HTTP_USER_AGENT"];
      $same_http_ip = $_SESSION["User"]["HTTP_IP"] == $_SERVER["HTTP_X_FORWARDED_FOR"];
      $timed_out = $_SESSION["User"]["TimeOut"] <= time();

      if((!$same_remote_ip && !$same_http_ip) || !$same_agent || $timed_out) return false;

      return true;
    }

    // ? GET_SESSION - Returns Session if exists
    public static function Session_Get($return_session = false){

      $session_exists = isset($_SESSION["User"]);
      $access_token_exists = isset($_SESSION["User"]["AccessToken"]);
      $refresh_token_exists = isset($_SESSION["User"]["RefreshToken"]);
      $valid_session = self::Session_Valid();

      if($session_exists && !$valid_session) {

      }

      // ? Used for this->Logout; session is invalid but we still need a username to logout with.
      if($session_exists && $return_session) return $_SESSION["User"];

      if(!$session_exists || !$access_token_exists || !$refresh_token_exists || !$valid_session) return false;

      return $_SESSION["User"];
    }

    public static function Session_Update_Timeout(){
      $_SESSION["User"]["TimeOut"] = (time() + (60 * self::$TIME_OUT));
    }
    // *************************************************
    // *********** END SESSION METHODS *****************
    // *************************************************


    // *************************************************
    // ************** UTIL METHODS *********************
    // *************************************************

    // ? EXTRACT_USER_INFO - Extracts info from aws_result_object
    // ? @return <array> user_info[]
    public static function Extract_User_Info($aws_result_obj){
      try{
        $info = $aws_result_obj;
        $user_info = [];

				$user_info['this_obj'] = $info;
        $user_info['Username'] = $info['Username'];
        $user_info['MfaSMSEnabled'] = (!empty($info["UserMFASettingList"]) ? 1 : 0);
        $user_info['Enabled'] = $info['Enabled'];
        $user_info['UserCreateDate'] = $info['UserCreateDate']->__toString();
        $user_info['UserLastModifiedDate'] = $info['UserLastModifiedDate']->__toString();
        $user_info['UserStatus'] = $info['UserStatus'];
        $attributes = $info['UserAttributes'] ?? ($info['Attributes'] ?? null);

        for($i=0; $i < sizeof($attributes); $i++){
          $key = $attributes[$i]["Name"];
          $value = $attributes[$i]["Value"];
          $user_info[$key] = $value;

        }

        return $user_info;

      } catch(\Exception $ex){
        error_log("cognito.class.php->Extract_User_Info(): $ex");
        return false;
      }

    }

    // ? Safe Redirect to page
    public static function Load_Page(string $page){

      header("Location: " . $page);
      die();

    }

    // ? Sends POST data to URL
    // ? @returns <array> response JSON
    private function Send_Post(string $url, string $data){
      try{
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $response = curl_exec($ch);
        return json_decode($response, true);
      } catch(\Exception $e){
        error_log("Cognito.class.php->Send_Post Error: cURL Error with Parameters: " . $data);
      }

      return false;
    }

    // *************************************************
    // ************** END UTIL METHODS *****************
    // *************************************************

  }
