<?php

  require_once $_SERVER["DOCUMENT_ROOT"] . '/includes/auth/cognito.class.php';

  // ? SETUP for Cognito Lib w/ MFA
  $COGNITO_CONFIG = [
    'POOL_ID' => getenv("COGNITO_POOL_ID"),
    'REGION' => getenv("COGNITO_REGION"),
    'APP_CLIENT_ID' => getenv("COGNITO_APP_CLIENT_ID"),
    'AWS_ACCESS_KEY' => getenv("AWS_ACCESS_KEY"),
    'AWS_ACCESS_SECRET_KEY' => getenv("AWS_ACCESS_SECRET_KEY"),
    'DOMAIN' => getenv("COGNITO_DOMAIN"),
    'LOGIN_REDIRECT_URI' => getenv("COGNITO_LOGIN_REDIRECT"),
    'HOSTED_LOGIN_URI' => getenv("COGNITO_HOSTED_LOGIN")
  ];

  define("SITE_CURRENT_PAGE", basename($_SERVER["PHP_SELF"]));
  const SITE_PAGE_INDEX = "/callback.php";
  const SITE_PAGE_LOGIN = "/login.php";
  define("SITE_HOSTED_LOGIN", $COGNITO_CONFIG["HOSTED_LOGIN_URI"]);
  define("SITE_CHANGE_PASSWD", $COGNITO_CONFIG["DOMAIN"] . "/forgotPassword?response_type=code&client_id=" . $COGNITO_CONFIG["APP_CLIENT_ID"] . "&redirect_uri=" . $COGNITO_CONFIG["LOGIN_REDIRECT_URI"]);

  $auth = new CognitoAuth($COGNITO_CONFIG, true);
