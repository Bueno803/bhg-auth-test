<?php
declare(strict_types=1);

use Slim\Factory\AppFactory;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/src/bootstrap.php';

$app = AppFactory::create();

// CORS Middleware - MUST be added before other middleware
$corsMiddleware = function (Request $request, RequestHandler $handler): Response {
    $response = $handler->handle($request);
    
    return $response
        ->withHeader('Access-Control-Allow-Origin', 'http://localhost:3000')
        ->withHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        ->withHeader('Access-Control-Allow-Credentials', 'true')
        ->withHeader('Access-Control-Max-Age', '86400'); // Cache preflight for 24 hours
};

$app->add($corsMiddleware);

// Handle ALL preflight OPTIONS requests - IMPORTANT: This must come BEFORE other routes
$app->options('/{routes:.*}', function (Request $request, Response $response) {
  // Preflight request. Reply successfully:
    return $response;
  });
  
  
  $app->addErrorMiddleware(true, true, true);
  
  // Add JSON parsing middleware (getParsedBody() will only automatically parses form data by default so we need this to handle JSON requests)
  $app->addBodyParsingMiddleware();
  
  // Authentication Middleware
  $authMiddleware = function (Request $request, RequestHandler $handler) use ($auth): Response {
      if (!$auth->isLoggedIn()) {
          $response = new \Slim\Psr7\Response();
          $payload = ['status' => false, 'message' => 'Authentication required'];
          $response->getBody()->write(json_encode($payload));
          return $response
              ->withHeader('Content-Type', 'application/json')
              ->withStatus(401);
      }
      
      return $handler->handle($request);
  };
// Health check / root
$app->get('/', function (Request $request, Response $response) {
    $response->getBody()->write('PHP-Auth Slim API is running (Ace Auth)');
    return $response->withHeader('Content-Type', 'text/plain');
});

$app->post('/register', function (Request $request, Response $response) use ($auth) {
    $data = (array)$request->getParsedBody();
    $email = $data['email'] ?? '';
    $password = $data['password'] ?? '';
    $link = '';

    try {
        $userId = $auth->register($email, $password, null, function ($selector, $token) use (&$link) {
            // Here you would send the verification email
            // For testing purposes, we can just output the token
            error_log("Verification token: " . $selector . ':' . $token);

            $link = sprintf(
                'http://%s/verify_email.php?selector=%s&token=%s',
                $_SERVER['HTTP_HOST'],
                urlencode($selector),
                urlencode($token)
            );
            
          });
          error_log('Verification link (testing only): ' . $link);

        $payload = ['status' => true, 'link' => $link, 'message' => 'Registration successful', 'userId' => $userId];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
    }
    catch (\Delight\Auth\InvalidEmailException $e) {
        $payload = ['status' => false, 'message' => 'Invalid email address'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    catch (\Delight\Auth\InvalidPasswordException $e) {
        $payload = ['status' => false, 'message' => 'Invalid password'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    catch (\Delight\Auth\UserAlreadyExistsException $e) {
        $payload = ['status' => false, 'message' => 'User already exists'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(409);
    }
    catch (\Delight\Auth\TooManyRequestsException $e) {
        $payload = ['status' => false, 'message' => 'Too many requests'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(429);
    }
});

$app->get('/logout', function (Request $request, Response $response) use ($auth) {
    $auth->logOut();
    $payload = ['status' => true, 'message' => 'Logged out successfully'];
    $response->getBody()->write(json_encode($payload));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->post('/login', function (Request $request, Response $response) use ($auth) {
    $data = (array)$request->getParsedBody();
    $email = $data['email'] ?? '';  // or use 'email' if you want email login
    $password = $data['password'] ?? '';
    $rememberDuration = 120;

    try {
      $auth->login($email, $password, $rememberDuration);  // FIXED: use $username, not $email

      // Debug: Show session info after login
        $debugInfo = [
            'session_id' => session_id(),
            'session_data' => $_SESSION ?? [],
            'headers_sent' => headers_list(),
        ];

      $payload = [
        'status' => true, 
        'message' => 'Login successful',
        'user' => [
          'id' => (int) $auth->getUserId(),
          'email' => (string) $auth->getEmail(),  // FIXED: getEmail(), not getUserEmail()
          // 'username' => (string) $auth->getUsername(),
        ],
        'debug' => $debugInfo // Add debug info
        ];

      $response->getBody()->write(json_encode($payload));
      return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }
    catch (\Delight\Auth\InvalidEmailException $e) {
      $payload = ['status' => false, 'message' => 'Incorrected Login Information', 'data' => $data];
      $response->getBody()->write(json_encode($payload));
      return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    catch (\Delight\Auth\InvalidPasswordException $e) {
      $payload = ['status' => false, 'message' => 'Incorrected Login Information', 'data' => $data];
      $response->getBody()->write(json_encode($payload));
      return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    catch (\Delight\Auth\EmailNotVerifiedException $e) {
      $payload = ['status' => false, 'message' => 'Email not verified'];
      $response->getBody()->write(json_encode($payload));
      return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    catch (\Delight\Auth\TooManyRequestsException $e) {
      $payload = ['status' => false, 'message' => 'Too many requests'];
      $response->getBody()->write(json_encode($payload));
      return $response->withHeader('Content-Type', 'application/json')->withStatus(429);
    }
});  // FIXED: Added missing semicolon

// Add this route to your public/index.php
$app->get('/debug-session', function (Request $request, Response $response) use ($auth) {
    $debugInfo = [
        'session_id' => session_id(),
        'session_data' => $_SESSION ?? [],
        'cookies_received' => $_COOKIE ?? [],
        'is_logged_in' => $auth->isLoggedIn(),
        'session_status' => session_status(),
        'session_name' => session_name(),
    ];
    
    if ($auth->isLoggedIn()) {
        $debugInfo['user_id'] = $auth->getUserId();
        $debugInfo['user_email'] = $auth->getEmail();
    }
    
    $response->getBody()->write(json_encode($debugInfo, JSON_PRETTY_PRINT));
    return $response->withHeader('Content-Type', 'application/json');
});

// Who am I (GET)
$app->get('/whoami', function (Request $request, Response $response) use ($auth) {
    if ($auth->isLoggedIn()) {
        $payload = [
            'loggedIn' => true,
            'user' => [
                'id' => (int) $auth->getUserId(),
                'email' => (string) $auth->getEmail(),
                // 'username' => (string) $auth->getUsername(),
            ],
        ];
    } else {
        $payload = ['loggedIn' => false];
    }

    $response->getBody()->write(json_encode($payload));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->get('/protected', function (Request $request, Response $response) {
    $payload = ['status' => true, 'message' => 'You have accessed a protected route'];
    $response->getBody()->write(json_encode($payload));
    return $response->withHeader('Content-Type', 'application/json');
})->add($authMiddleware);

$app->run();