# zf2-multi-factor-authentication
This is a sample implementation of Google multi-factor authentication (MFA) for Zend Framework 2.

Implementation by Team CODIFIC • We code terrific.

MIT License http://opensource.org/licenses/MIT.

# Specification
This plugin implements the Google multi-factor authentication using a one-time token that is valid for maximum 8 minutes (configurable). Even if a username/password combination is leaked, brute forced or dictionary attacked the MFA will make sure the attacker will still not be able to login as Google MGA 

# Installation
Add the plugin to your composer.json by using the following line:
```json
"codific/zf2-multi-factor-authentication": "dev-master"
```
and run 
```bash
php composer.phar update
```

# Usage
The authenticated users should have 2 additional attributes in the database.
```sql
`secretKey` varchar(100) NOT NULL default ''
`mfaEnabled` tinyint(1) NOT NULL default 0
```

Upon a successful login redirect the authenticated user to the mfa screen. Here is a sample action for the MFA.
Note that we save the authenticated user in a cache variable and we clear the authentication storage before redirecting. After a successful MFA we restore the storage from the cache.
```php
    /**
     * Check multi-factor authentication after a successful login.
     *
     * @return \Zend\View\Model\ViewModel
     */
    public function checkmfaAction()
    {
        $data = $this->cache->authenticatedUser;
        $request = $this->getRequest();
        if($request->isPost()) {
            $postData = $request->getPost();
            $googleAuth = new \Codific\Authenticator($data->secretKey);
            if($googleAuth->verifyCode($postData->pin, 4)) //the second parameter specifies the validity of the MFA token in minutes
            {
                $this->cache->authenticatedUser->verifyMFA = 1;
                $auth = new AuthenticationService();
                $auth->getStorage()->write($data);
                return $this->redirect()->toUrl("/admin/index/index");
            }
            else
            {
                $this->cache->error = "Your code is invalid. Please try again.";
            }
        }
        return $this->view;
    }
```

Here is a sample of the view code.
```
<header>
    <span class="widget-icon"><i class="fa fa-list"></i></span>
    <h2>2-step verification</h2>
  </header>
  <div class='well'>
    <form action="/admin/login/checkmfa" method="POST" name="login" class="form-horizontal" id="login">
      <fieldset class="form-horizontal">
        <div class="form-group ">
          <label>Enter verification code</label>
          <input type="tel" pattern="[0-9 ]*" id="totpPin" name="pin" dir="ltr" autocomplete="off" placeholder="Enter 6-digit code" autofocus class="form-control">
        </div>
        <div class="form-group ">
          <button type="submit" name="done" id="submitbutton" class="button-fix btn-primary form-control btn" value="">Submit</button>
        </div>
      </fieldset>
    </form>
  </div>
```