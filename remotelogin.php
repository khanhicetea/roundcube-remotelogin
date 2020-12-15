<?php

class remotelogin extends rcube_plugin
{
    public $task = 'login';

    private $secret;
    private $static_password;

    function init()
    {
        $rcmail = rcube::get_instance();
        $this->secret = $rcmail->config->get('remotelogin_secret', '');
        $this->static_password = $rcmail->config->get('remotelogin_static_password', '');

        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('authenticate', array($this, 'authenticate'));
    }

    function startup($args)
    {
        if (empty($_SESSION['user_id']) && !empty($_GET['_remotelogin'])) {
            $args['action'] = 'login';
        }

        return $args;
    }

    function authenticate($args)
    {
        if (!empty($_GET['_remotelogin'])) {
            $user = $_GET['_remotelogin'];
            $hash = $_GET['_remotehash'] ?? null;

            if ($hash && hash_hmac('sha256', $user, $this->secret) == $hash) {
                $args['user'] = $user;
                $args['pass'] = $this->static_password;
                $args['cookiecheck'] = false;
                $args['valid'] = true;
            }
        }

        return $args;
    }
}