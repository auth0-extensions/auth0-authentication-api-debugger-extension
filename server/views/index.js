module.exports = `<html lang="en">
<head>
  <title>Auth0 - Protocol Debugger</title>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=Edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="shortcut icon" href="https://cdn.auth0.com/styleguide/4.6.13/lib/logos/img/favicon.png">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="https://cdn.auth0.com/styles/zocial.min.css">
  <link rel="stylesheet" type="text/css" href="https://cdn.auth0.com/manage/v0.3.1715/css/index.min.css">
  <link rel="stylesheet" type="text/css" href="https://cdn.auth0.com/styleguide/4.6.13/index.css">
  <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/highlight.js/9.7.0/styles/github.min.css">
  <script src="//cdnjs.cloudflare.com/ajax/libs/highlight.js/9.7.0/highlight.min.js"></script>
  <style type="text/css">
    p.controls-info {
      font-size: 13px;
      color: #000;
      opacity: .56;
      line-height: 18px;
      margin: 8px 0 0 0;
      clear: both;
    }
    code.xml {
      color: black !important;
      background-color: #fbfbfb !important;
      margin-top: -25px !important;
      margin-bottom: -51px !important;
    }
    pre.json-object {
      background-color: #fbfbfb;
      border: 1px solid #f1f1f1;
      border-radius: 0px;
      padding: 10px 10px;
      font-size: 12px;
    }
    .json-object .json-key {
      color: #16214D;
    }
    .json-object .json-value {
      color: #01B48F;
    }
    .json-object .json-string {
      color: #EB5424;
    }
  </style>
  <script type="text/javascript">
    if (!sessionStorage.getItem("token")) {
      window.location.href = '{{baseUrl}}/login';
    }
  </script>
</head>
<body>
<div id="app">
  <div>
    <header class="dashboard-header">
      <nav role="navigation" class="navbar navbar-default">
        <div class="container">
          <div class="navbar-header">
            <h1 class="navbar-brand" style="padding-top: 0px;"><a href="https://manage.auth0.com"><span>Auth0</span></a></h1>
          </div>
          <div id="navbar-collapse" class="collapse navbar-collapse">
            <ul class="nav navbar-nav navbar-right">
              <li><a target="_blank" href="https://auth0.com/support">Help &amp; Support</a></li>
              <li><a target="_blank" href="https://auth0.com/docs/extensions/authentication-api-debugger">Documentation</a></li>
            </ul>
          </div>
        </div>
      </nav>
    </header>
    <div class="container">
      <div class="row">
        <div class="col-xs-12">
          <div class="row">
            <div class="col-xs-12">
              <h1 class="pull-left" style="padding-top: 10px;">Authentication API Debugger</h1>
            </div>
          </div>
          <div class="row">
            <div class="col-xs-12">
            	<div class="widget-title title-with-nav-bars">
            		<ul id="tabs" class="nav nav-tabs">
            			<li class="active"><a data-toggle="tab" href="#login"><span class="tab-title">Login</span></a></li>
              		<li><a data-toggle="tab" href="#request"><span class="tab-title">Request</span></a></li>
            		</ul>
            	</div>
            	<div id="content-area" class="tab-content">
                <div id="login" class="tab-pane active">
                  <div class="row">
                    <div class="col-xs-12">
                      <div class="alert alert-warning">Please note that this extension retrieves the Client ID and Client Secrets for your Applications using the Management API. This information is subsequently used to call Authentication API endpoints where applicable.</div>
                    </div>
                    <div class="col-xs-12">
                      <button id="reset_settings" class="btn btn-success">Clear Settings</button>
                      <p class="controls-info">Hit this button if you want to remove everything from local storage.</p>
                    </div>
                    <div class="col-xs-12" style="margin-top: 25px">
                      <div>
                        <div class="widget-title title-with-nav-bars">
                      		<ul id="login-tabs" class="nav nav-tabs">
                      			<li class="active"><a data-toggle="tab" href="#configuration"><span class="tab-title">Configuration</span></a></li>
                        		<li><a data-toggle="tab" href="#oauth2"><span class="tab-title">OAuth2 / OIDC</span></a></li>
                        		<li><a data-toggle="tab" href="#other-flows"><span class="tab-title">Other Flows</span></a></li>
                      		</ul>
                      	</div>
                      	<div id="login-content-area" class="tab-content">
                          <div id="configuration" class="tab-pane active">
                            <p>Enter your account settings and additional application settings here (these will be persisted in localstorage).</p>
                            <form class="form-horizontal col-xs-12">
                              <div class="form-group"><label class="col-xs-2 control-label">Domain</label>
                                <div class="col-xs-10">
                                  <input id="domain" readonly type="text" class="form-control" value="{{domain}}">
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">Application</label>
                                <div class="col-xs-10">
                                  <select id="client" class="form-control">
                                  </select>
                                  <input id="client_id" type="hidden" class="form-control">
                                  <input id="client_secret" type="hidden" class="form-control">
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">Callback URL</label>
                                <div class="col-xs-10">
                                  <input id="callback_url" readonly type="text" class="form-control" value="">
                                  <p class="controls-info">Make sure you configure this as the Callback Url on your application.</p>
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">SSO</label>
                                <div class="col-xs-3">
                                  <div class="ui-switch">
                                    <input id="use_sso" type="checkbox"/>
                                    <label class="status"></label>
                                  </div>
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">State</label>
                                <div class="col-xs-10">
                                  <input id="state" type="text" class="form-control" value="">
                                  <p class="controls-info">This might translate to RelayState or wctx depending on the protocol.</p>
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">Connection</label>
                                <div class="col-xs-10">
                                  <input id="connection" type="text" class="form-control" value="">
                                  <p class="controls-info">Specify the name of a connection to skip the login page (eg: <strong>google-oauth2</strong>).</p>
                                </div>
                              </div>
                            </form>
                          </div>
                          <div id="oauth2" class="tab-pane">
                            <div class="alert alert-info">Specification: <a href="https://tools.ietf.org/html/rfc6749#section-1.3.3">OAuth2</a></div>
                            <h5>User Flows</h5>
                            <button id="oidc_oauth2" class="btn btn-primary">OAuth2 / OIDC Login</button>
                            <button id="oauth2_code_exchange" class="btn btn-primary">OAuth2 Code Exchange</button>
                            <button id="oauth2_refresh_token_exchange" class="btn btn-primary">OAuth2 Refresh Token Exchange</button>
                            <p class="controls-info">The exchanges will use the Client ID (and optionally Secret) from the Configuration tab.</p>
                            <h5>Machine to Machine</h5>
                            <button id="oauth2_client_credentials" class="btn btn-primary">OAuth2 Client Credentials</button>
                            <p class="controls-info">This will use the Client ID and Secret from the Configuration tab.</p>
                            <h5>Resource Owner Password Credentials</h5>
                            <form class="form-horizontal col-xs-12">
                              <div class="form-group"><label class="col-xs-2 control-label">Username</label>
                                <div class="col-xs-10">
                                  <input id="username" type="text" class="form-control" value="">
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">Password</label>
                                <div class="col-xs-6">
                                  <input id="password" type="password" class="form-control" value="">
                                  <p class="controls-info">Optional: Only store passwords for test accounts here.</p>
                                </div>
                                <div class="col-xs-4">
                                  <div class="ui-switch ui-switch-labeled ui-switch-xl">
                                    <input id="save_password" type="checkbox" />
                                    <label data-label-true="Save in Local Storage" data-label-false="Don't Save in Local Storage" class="status"></label>
                                  </div>
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">Device</label>
                                <div class="col-xs-10">
                                  <input id="device" type="text" class="form-control" value="">
                                  <p class="controls-info">This field is here for legacy purposes. It's not part of the spec.</p>
                                </div>
                              </div>
                            </form>
                            <button id="oauth2_password_grant" class="btn btn-primary">Password Grant</button>
                            <button id="oauth2_ro" class="btn btn-primary">Resource Owner Endpoint</button>
                            <p class="controls-info">The Resource Owner Endpoint is here for legacy purposes. It's not part of the spec.</p>
                            <h5>Delegation</h5>
                            <p class="controls-info">Not part of the spec - this is here for legacy purposes only.</p>
                            <form class="form-horizontal col-xs-12">
                              <div class="form-group"><label class="col-xs-2 control-label">ID Token</label>
                                <div class="col-xs-10">
                                  <input id="delegation_id_token" type="text" class="form-control" value="">
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">Refresh Token</label>
                                <div class="col-xs-10">
                                  <input id="delegation_refresh_token" type="text" class="form-control" value="">
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">Target Client ID</label>
                                <div class="col-xs-10">
                                  <input id="delegation_target" type="text" class="form-control" value="">
                                </div>
                              </div>
                            </form>
                            <button id="oauth2_delegation" class="btn btn-primary">Delegation</button>
                            <h5>Settings</h5>
                            <p>The following settings might behave differently if you're using OAuth2 as a Service (Preview)</p>
                            <form class="form-horizontal col-xs-12">
                              <div class="form-group">
                                <label class="col-xs-2 control-label">PKCE</label>
                                <div class="col-xs-10">
                                  <div class="ui-switch">
                                    <input id="use_pkce" type="checkbox"/>
                                    <label class="status"></label>
                                  </div>
                                  <p class="controls-info">The PKCE (Proof Key for Code Exchange by OAuth Public Clients) or Hybrid Flow is a better alternative to the implicit flow for Mobile Apps. In Auth0, make sure you set the application type to "Native".</p>
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">Audience</label>
                                <div class="col-xs-7">
                                  <input id="audience" type="text" class="form-control" value="">
                                  <p class="controls-info">Only required when you need an access token.</p>
                                </div>
                                <div class="col-xs-3">
                                  <div class="ui-switch ui-switch-labeled ui-switch-md">
                                    <input id="use_audience" type="checkbox" />
                                    <label data-label-true="Save in Local Storage" data-label-false="Use Audience" class="status"></label>
                                  </div>
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">Authorization Code</label>
                                <div class="col-xs-10">
                                  <input id="authorization_code" type="text" class="form-control" value="{{authorization_code}}">
                                  <p class="controls-info">Set the response type to <strong>code</strong> and then press the <strong>OIDC / OAuth2</strong> button to get an authorization code.</p>
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">Code Verifier</label>
                                <div class="col-xs-10">
                                  <input id="code_verifier" type="text" class="form-control" value="{{code_verifier}}">
                                  <p class="controls-info">If you're using <strong>PKCE</strong>, this is what will be used instead of the Client Secret.</p>
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">Refresh Token</label>
                                <div class="col-xs-10">
                                  <input id="refresh_token" type="text" class="form-control" value="{{refresh_token}}">
                                  <p class="controls-info">Set the response type to <strong>code</strong>, request the <strong>offline_access</strong> scope and then press the <strong>OIDC / OAuth2</strong> button to get an authorization code.</p>
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">Response Type</label>
                                <div class="col-xs-10">
                                  <input id="response_type" type="text" class="form-control" value="">
                                  <p class="controls-info">You can try a mix of <strong>code</strong>, <strong>id_token</strong>, <strong>token</strong></p>
                                </div>
                              </div>
                              <div class="form-group">
                                <label class="col-xs-2 control-label">Response Mode</label>
                                <div class="col-xs-10">
                                  <input id="response_mode" type="text" class="form-control" value="">
                                  <p class="controls-info">You can try something like <strong>fragment</strong>, <strong>query</strong> or <strong>form_post</strong></p>
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">Scope</label>
                                <div class="col-xs-10">
                                  <input id="scope" type="text" class="form-control" value="openid name email">
                                  <p class="controls-info">You can try something like <strong>openid name email read:appointments</strong></p>
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">Prompt</label>
                                <div class="col-xs-10">
                                  <input id="prompt" type="text" class="form-control" value="openid name email">
                                  <p class="controls-info">You can try something like <strong>consent</strong> or <strong>login</strong></p>
                                </div>
                              </div>
                              <div class="form-group"><label class="col-xs-2 control-label">Nonce</label>
                                <div class="col-xs-10">
                                  <input id="nonce" type="text" class="form-control" value="">
                                  <p class="controls-info">Like the OAuth2 state parameter. Required for OIDC Implicit Flow.</p>
                                </div>
                              </div>
                            </form>
                          </div>
                          <div id="other-flows" class="tab-pane">
                            <button id="saml" class="btn btn-primary">SAML</button>
                            <button id="wsfed" class="btn btn-primary">WS-Federation</button>
                            <h5>Logout</h5>
                            <button id="logout" class="btn btn-primary">Logout</button>
                            <button id="logout-federated" class="btn btn-primary">Logout (Federated)</button>
                            <h5>SSO</h5>
                            <button id="sso-data" class="btn btn-primary">Get SSO Data</button>
                            <div id="sso-data-output"></div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
            		<div id="request" class="tab-pane">
                  <div class="row">
                    <div class="col-xs-12">
                      <div>
                        <h5>Details</h5>
                        <form class="form-horizontal col-xs-12">
                          <div class="form-group"><label class="col-xs-1 control-label">Method</label>
                            <div class="col-xs-11"><input type="text" readonly="" class="form-control" value="{{method}}"></div>
                          </div>
                          <div class="form-group"><label class="col-xs-1 control-label">Url</label>
                            <div class="col-xs-11"><input type="text" readonly="" class="form-control" value="{{baseUrl}}"></div>
                          </div>
                        </form>
                      </div>
                    </div>
                  </div>
                  {{#if body}}
                  <div class="row">
                    <div class="col-xs-12">
                      <div>
                        <h5>Body</h5>
                      </div>
                    </div>
                    <div class="col-lg-12">
                      <pre class="json-object">{{{body}}}</pre>
                    </div>
                  </div>
                  {{/if}}
                  {{#if id_token}}
                  <div class="row">
                    <div class="col-xs-12">
                      <div>
                        <h5>ID Token</h5>
                      </div>
                    </div>
                    <div class="col-lg-12">
                      <pre class="json-object">{{{id_token}}}</pre>
                    </div>
                  </div>
                  {{/if}}
                  {{#if access_token}}
                  <div class="row">
                    <div class="col-xs-12">
                      <div>
                        <h5>Access Token</h5>
                      </div>
                    </div>
                    <div class="col-lg-12">
                      <pre class="json-object">{{{access_token}}}</pre>
                    </div>
                  </div>
                  {{/if}}
                  <div id="hash_fragment"></div>
                  {{#if samlResponse}}
                  <div class="row">
                    <div class="col-xs-12">
                      <div>
                        <h5>SAML Response</h5>
                      </div>
                    </div>
                    <div class="col-lg-12">
                      <pre>
                        <code class="xml">{{{samlResponse}}}</code>
                      </pre>
                    </div>
                  </div>
                  {{/if}}
                  {{#if wsFedResult}}
                  <div class="row">
                    <div class="col-xs-12">
                      <div>
                        <h5>WS-Federation Result</h5>
                      </div>
                    </div>
                    <div class="col-lg-12">
                      <pre>
                        <code class="xml">{{{wsFedResult}}}</code>
                      </pre>
                    </div>
                  </div>
                  {{/if}}
                  {{#if query}}
                  <div class="row">
                    <div class="col-xs-12">
                      <div>
                        <h5>Query</h5>
                      </div>
                    </div>
                    <div class="col-lg-12">
                      <pre class="json-object">{{{query}}}</pre>
                    </div>
                  </div>
                  {{/if}}
                  <div class="row">
                    <div class="col-xs-12">
                      <div>
                        <h5>Headers</h5>
                      </div>
                    </div>
                    <div class="col-lg-12">
                      <pre class="json-object">{{{headers}}}</pre>
                    </div>
                  </div>
            		</div>
            		<div id="login" class="tab-pane">
            		</div>
            	</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div id="modal-dialog" tabindex="-1" role="dialog" aria-hidden="true" class="modal">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header has-border">
          <button type="button" data-dismiss="modal" class="close"><span aria-hidden="true">×</span><span class="sr-only">Close</span></button>
          <h4 id="modal-title" class="modal-title"></h4>
        </div>
        <div id="modal-body" class="modal-body"></div>
        <div class="modal-footer">
          <button data-dismiss="modal" id="close-modal" type="button" class="btn btn-primary">Close</button>
        </div>
      </div>
    </div>
  </div>
</div>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/1.11.3/jquery.js"></script>
<script src="//cdn.jsdelivr.net/lodash/4.17.0/lodash.min.js"></script>
<script src="//cdn.auth0.com/w2/auth0-6.js"></script>
<script type="text/javascript" src="//cdn.auth0.com/manage/v0.3.1715/js/bundle.js"></script>
<script>hljs.initHighlightingOnLoad();</script>
<script type="text/javascript">
var clients = [];

function read() {
  $('#audience').val(localStorage.getItem('auth_debugger_audience'));
  $('#callback_url').val(window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '') + window.location.pathname);
  $('#client').val(localStorage.getItem('auth_debugger_client'));
  //$('#client_id').val(localStorage.getItem('auth_debugger_client_id') || 'IsTxQ7jAYAXL5r5HM4L1RMzsSG0UHeOy');
  //$('#client_secret').val(localStorage.getItem('auth_debugger_client_secret'));
  $('#code_verifier').val(localStorage.getItem('auth_debugger_code_verifier'));
  $('#connection').val(localStorage.getItem('auth_debugger_connection'));
  $('#device').val(localStorage.getItem('auth_debugger_device'));
  //$('#domain').val(localStorage.getItem('auth_debugger_domain') || 'sandrino.auth0.com');
  $('#password').val(localStorage.getItem('auth_debugger_password'));
  $('#delegation_target').val(localStorage.getItem('auth_debugger_delegation_target'));
  $('#prompt').val(localStorage.getItem('auth_debugger_prompt') || '');
  $('#nonce').val(localStorage.getItem('auth_debugger_nonce') || '');
  $('#refresh_token').val(localStorage.getItem('auth_debugger_refresh_token'));
  $('#response_mode').val(localStorage.getItem('auth_debugger_response_mode') || '');
  $('#response_type').val(localStorage.getItem('auth_debugger_response_type') || 'token');
  //$('#save_client_secret').prop('checked', localStorage.getItem('auth_debugger_client_secret') && localStorage.getItem('auth_debugger_client_secret').length);
  $('#save_password').prop('checked', localStorage.getItem('auth_debugger_password') && localStorage.getItem('auth_debugger_password').length);
  $('#scope').val(localStorage.getItem('auth_debugger_scope') || 'openid name email nickname');
  $('#state').val(localStorage.getItem('auth_debugger_state') || 'my-custom-state');
  $('#username').val(localStorage.getItem('auth_debugger_username'));
  if (localStorage.getItem('auth_debugger_use_audience') === "1") {
    $('#use_audience').prop('checked', 'checked');
  }
  if (localStorage.getItem('auth_debugger_use_pkce') === "1") {
    $('#use_pkce').prop('checked', 'checked');
  }
  if (localStorage.getItem('auth_debugger_use_sso') === "1") {
    $('#use_sso').prop('checked', 'checked');
  }
}
function save() {
  localStorage.setItem('auth_debugger_audience', $('#audience').val());
  localStorage.setItem('auth_debugger_client', $('#client').val());
  //localStorage.setItem('auth_debugger_client_id', $('#client_id').val());
  //localStorage.setItem('auth_debugger_client_secret', $('#save_client_secret').is(':checked') ? $('#client_secret').val() : '');
  localStorage.setItem('auth_debugger_code_verifier', $('#code_verifier').val());
  localStorage.setItem('auth_debugger_connection', $('#connection').val());
  //localStorage.setItem('auth_debugger_domain', $('#domain').val());
  localStorage.setItem('auth_debugger_delegation_target', $('#delegation_target').val());
  localStorage.setItem('auth_debugger_device', $('#device').val());
  localStorage.setItem('auth_debugger_password', $('#save_password').is(':checked') ? $('#save_password').val() : '');
  localStorage.setItem('auth_debugger_prompt', $('#prompt').val());
  localStorage.setItem('auth_debugger_nonce', $('#nonce').val());
  localStorage.setItem('auth_debugger_refresh_token', $('#refresh_token').val());
  localStorage.setItem('auth_debugger_response_mode', $('#response_mode').val());
  localStorage.setItem('auth_debugger_response_type', $('#response_type').val());
  localStorage.setItem('auth_debugger_scope', $('#scope').val());
  localStorage.setItem('auth_debugger_state', $('#state').val());
  localStorage.setItem('auth_debugger_use_audience', $('#use_audience').is(':checked') ? "1" : "0");
  localStorage.setItem('auth_debugger_use_pkce', $('#use_pkce').is(':checked') ? "1" : "0");
  localStorage.setItem('auth_debugger_use_sso', $('#use_sso').is(':checked') ? "1" : "0");
  localStorage.setItem('auth_debugger_username', $('#username').val());
}
function bindClients() {
  _.each(clients, function(client) {
    $('#client').append($('<option>', {
        value: client.client_id,
        text : client.name
    }));
  })
}
function setSelectedClientSecrets() {
  selectedClient = _.find(clients, { 'client_id': $('#client').val()});

    if (selectedClient) {
      $('#client_id').val(selectedClient.client_id);
      $('#client_secret').val(selectedClient.client_secret);
    } else {
      $('#client_id').val('');
      $('#client_secret').val('');
    }
}
function setSelectedClientSecrets() {
  selectedClient = _.find(clients, { 'client_id': $('#client').val() });

  if (selectedClient) {
    $('#client_id').val(selectedClient.client_id);
    $('#client_secret').val(selectedClient.client_secret);
  } else {
    $('#client_id').val('');
    $('#client_secret').val('');
  }
}
function handleSuccessRequest(url, opt, data) {
  data.request = opt;
  if (data.refresh_token) {
    $('#refresh_token').val(data.refresh_token);
  }
  if (data.request.password) {
    data.request.password = '*****************';
  }
  if (data.request.client_secret) {
    data.request.client_secret = '*****************';
  }
  $.ajax({ type: "POST", url: '{{baseUrl}}/request', data: JSON.stringify(data), contentType: 'application/json' })
    .done(function (data) {
      $('#modal-body').html(data);
      $('#modal-body').prepend($('<pre/>', { 'class': 'json-object', 'html': 'POST ' + url }));
    })
    .fail(function (err) {
      $('#modal-body').html('<p>Error decoding the response.</p>');
      $('<pre/>', { 'class': 'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#modal-body');
    });
}
function handleErrorRequest(url, opt, err) {
  if (opt.password) {
    opt.password = '*****************';
  }
  if (opt.client_secret) {
    opt.client_secret = '*****************';
  }
  $.ajax({ type: "POST", url: '{{baseUrl}}/request', data: JSON.stringify({ request: opt, err: err }), contentType: 'application/json' })
    .done(function (data) {
      $('#modal-body').html(data);
      $('#modal-body').prepend($('<pre/>', { 'class': 'json-object', 'html': 'POST ' + url }));
    })
    .fail(function (err) {
      $('#modal-body').html('<p>Error decoding the response.</p>');
      $('<pre/>', { 'class': 'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#modal-body');
    });
}
function executeRequest(title, url, opt) {
  save();
  $('#modal-title').html(title);
  $('#modal-body').html('Loading...');
  $('#modal-dialog').modal({ show: true });
  $.post(url, opt)
    .done(function (data) {
      handleSuccessRequest(url, opt, data);
    })
    .fail(function (err) {
      handleErrorRequest(url, opt, err);
    });
}
function executeBackendRequest(title, url, backendUrl, opt) {
  save();
  $('#modal-title').html(title);
  $('#modal-body').html('Loading...');
  $('#modal-dialog').modal({ show: true });
  $.post(backendUrl, opt)
    .done(function (data) {
      data.request = opt;
      handleSuccessRequest(url, opt, data);
    })
    .fail(function (err) {
      handleErrorRequest(url, opt, err);
    });
}
function executeTokenExchange(title, opt) {
  var url =  'https://' + $('#domain').val() + '/oauth/token';
  var backendUrl = '{{baseUrl}}/request/token';
  executeBackendRequest(title, url, backendUrl, opt);
}
function executeCodeExchange(title, opt) {
  var url =  'https://' + $('#domain').val() + '/oauth/token';
  var backendUrl = '{{baseUrl}}/request/code';
  executeBackendRequest(title, url, backendUrl, opt);
}
if (!window.location.origin) {
  window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
}
var callbackUrl = window.location.origin + window.location.pathname;
$(function () {
  function fetchAllClients(page, results) {
    page = page || 0;
    results = results || [];

    var perPage = 100;
    $.ajax({
      url: 'https://{{domain}}/api/v2/clients?page=' + page + '&per_page=' + perPage,
      type: 'GET',
      headers: {
        'Authorization': 'Bearer ' + sessionStorage.getItem("token")
      }}).done(
        function(data) {
          results = results.concat(data || []);
          if (data && data.length === perPage) {
            fetchAllClients(page + 1, results);
          } else {
            clients = _.map(results, function(client) { return _.pick(client, ['client_id', 'client_secret', 'name'] )} );
            bindClients();
            read();
            setSelectedClientSecrets();
          }
      }).fail(function(err) {
        if (err.status === 401 || err.status === 403) {
          sessionStorage.removeItem('token');
          sessionStorage.removeItem('apiToken');
          window.location.href = '/login';
        }
      });
  }
  fetchAllClients();

  if ("{{method}}" === 'POST' || (window.location.hash && window.location.hash.length > 1) || (window.location.search && window.location.search.length > 1 && window.location.search !== '?webtask_no_cache=1')) {
    $('#tabs a[href="#request"]').tab('show');
  }
  if (window.location.hash && window.location.hash.length > 1) {
    $('#hash_fragment').load(window.location.origin + window.location.pathname + '/hash?' + window.location.hash.replace(/^\#/,""));
  }
  $('#client').change(function(e) {
    setSelectedClientSecrets();
  });
  $('#saml').click(function(e) {
    e.preventDefault();
    save();
    var url = 'https://' + $('#domain').val() + '/samlp/' + $('#client_id').val() + '?RelayState=' + encodeURIComponent($('#state').val());
    url = url + '&redirect_uri=' + encodeURIComponent(callbackUrl);
    if ($('#connection').val() && $('#connection').val().length) {
      url = url + '&connection=' + encodeURIComponent($('#connection').val());
    }
    window.location.href = url;
  });
  $('#wsfed').click(function(e) {
    e.preventDefault();
    save();
    var url = 'https://' + $('#domain').val() + '/wsfed/' + $('#client_id').val() + '?wctx=' + encodeURIComponent($('#state').val());
    url = url + '&wreply=' + encodeURIComponent(callbackUrl);
    if ($('#connection').val() && $('#connection').val().length) {
      url = url + '&whr=' + encodeURIComponent($('#connection').val());
    }
    window.location.href = url;
  });
  $('#logout').click(function(e) {
    e.preventDefault();
    save();
    window.location.href = 'https://' + $('#domain').val() + '/v2/logout?client_id=' + $('#client_id').val() + '&returnTo=' + encodeURIComponent(callbackUrl);
  });
  $('#logout-federated').click(function(e) {
    e.preventDefault();
    save();
    window.location.href = 'https://' + $('#domain').val() + '/v2/logout?federated&client_id=' + $('#client_id').val() + '&returnTo=' + encodeURIComponent(callbackUrl);
  });
  $('#reset_settings').click(function(e) {
    e.preventDefault();
    for (key in localStorage) {
      if (key.indexOf('auth_debugger_') === 0) {
        delete localStorage[key];
      }
    }
    read();
  });
  $('#oauth2_client_credentials').click(function(e) {
    e.preventDefault();
    var opt = {
      audience: $('#audience').val(),
      client_id: $('#client_id').val(),
      client_secret: $('#client_secret').val(),
      grant_type: 'client_credentials'
    };
    executeRequest('OAuth2 - Client Credentials', 'https://' + $('#domain').val() + '/oauth/token', opt);
  });
  $('#oauth2_code_exchange').click(function(e) {
    e.preventDefault();
    var opt = {
      client_id: $('#client_id').val(),
      redirect_uri: callbackUrl,
      code: $('#authorization_code').val(),
      grant_type: 'authorization_code'
    };
    if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {
      opt.audience = $('#audience').val();
    }
    if ($('#use_pkce').is(':checked')) {
      opt.code_verifier = $('#code_verifier').val();
    } else {
      opt.client_secret = $('#client_secret').val();
    }
    executeCodeExchange('OAuth2 - Authorization Code Exchange', opt);
  });
  $('#oauth2_refresh_token_exchange').click(function(e) {
    e.preventDefault();
    var opt = {
      client_id: $('#client_id').val(),
      refresh_token: $('#refresh_token').val(),
      grant_type: 'refresh_token'
    };
    if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {
      opt.audience = $('#audience').val();
    }
    if ($('#use_pkce').is(':checked')) {
      opt.code_verifier = $('#code_verifier').val();
    } else {
      opt.client_secret = $('#client_secret').val();
    }
    executeTokenExchange('OAuth2 - Refresh Token Exchange', opt);
  });
  $('#oauth2_password_grant').click(function(e) {
    e.preventDefault();
    var opt = {
      client_id: $('#client_id').val(),
      username: $('#username').val(),
      password: $('#password').val(),
      grant_type: 'password',
      scope: $('#scope').val()
    };
    if ($('#connection').val() && $('#connection').val().length) {
      opt.connection = $('#connection').val();
    }
    executeRequest('OAuth2 - Password Grant', 'https://' + $('#domain').val() + '/oauth/token', opt);
  });
  $('#oauth2_ro').click(function(e) {
    e.preventDefault();
    if ($('#use_sso').is(':checked')) {
      save();
      var auth0 = new Auth0({
        domain: $('#domain').val(),
        clientID: $('#client_id').val(),
        callbackURL: callbackUrl
      });
      var options = {
        state: $('#state').val(),
        sso: $('#use_sso').is(':checked'),
        username: $('#username').val(),
        password: $('#password').val(),
        connection: $('#connection').val(),
        scope: $('#scope').val()
      };
      if ($('#device').val() && $('#device').val().length) {
        options.device = $('#device').val();
      }
      return auth0.login(options);
    }
    var opt = {
      client_id: $('#client_id').val(),
      username: $('#username').val(),
      password: $('#password').val(),
      grant_type: 'password',
      scope: $('#scope').val()
    };
    if ($('#connection').val() && $('#connection').val().length) {
      opt.connection = $('#connection').val();
    }
    if ($('#device').val() && $('#device').val().length) {
      opt.device = $('#device').val();
    }
    executeRequest('OAuth2 - Resource Owner', 'https://' + $('#domain').val() + '/oauth/ro', opt);
  });
  $('#oauth2_delegation').click(function(e) {
    e.preventDefault();
    var opt = {
      client_id: $('#client_id').val(),
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      scope: $('#scope').val()
    };
    if ($('#delegation_target').val() && $('#delegation_target').val().length) {
      opt.target = $('#delegation_target').val();
    }
    if ($('#delegation_id_token').val() && $('#delegation_id_token').val().length) {
      opt.id_token = $('#delegation_id_token').val();
    }
    if ($('#delegation_refresh_token').val() && $('#delegation_refresh_token').val().length) {
      opt.refresh_token = $('#delegation_refresh_token').val();
    }
    executeRequest('OAuth2 - Delegation', 'https://' + $('#domain').val() + '/delegation', opt);
  });
  $('#oidc_oauth2').click(function(e) {
    e.preventDefault();
    save();
    // Don't do this in production. The client should always generate the verifier, and not rely on a remote server to do this.
    $.get('{{baseUrl}}/pkce')
      .done(function(data) {
        var auth0 = new Auth0({
          domain: $('#domain').val(),
          clientID: $('#client_id').val(),
          callbackURL: callbackUrl
        });
        var options = {
          state: $('#state').val(),
          sso: $('#use_sso').is(':checked'),
        };
        if ($('#use_pkce').is(':checked')) {
          options.code_challenge = data.verifier_challenge;
          options.code_challenge_method = 'S256';
          localStorage.setItem('auth_debugger_code_verifier', data.verifier);
        }
        if ($('#scope').val() && $('#scope').val().length) {
          options.scope = $('#scope').val();
        }
        if ($('#connection').val() && $('#connection').val().length) {
          options.connection = $('#connection').val();
        }
        if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {
          options.audience = $('#audience').val();
        }
        if ($('#response_type').val() && $('#response_type').val().length) {
          options.response_type = $('#response_type').val();
        }
        if ($('#response_mode').val() && $('#response_mode').val().length) {
          options.response_mode = $('#response_mode').val();
        }
        if ($('#prompt').val() && $('#prompt').val().length) {
          options.prompt = $('#prompt').val();
        }
        if ($('#nonce').val() && $('#nonce').val().length) {
          options.nonce = $('#nonce').val();
        }
        auth0.login(options);
      });
  });
  $('#sso-data').click(function(e) {
    e.preventDefault();
    save();
    var auth0 = new Auth0({
      domain: $('#domain').val(),
      clientID: $('#client_id').val(),
      callbackURL: callbackUrl
    });
    $('#sso-data-output').html('Loading...');
    auth0.getSSOData(function(err, res) {
      $.ajax({ type: "POST", url: '{{baseUrl}}/request', data: JSON.stringify({ error: err, response: res }), contentType: 'application/json' })
        .done(function(data) {
          $('#sso-data-output').html(data);
        })
        .fail(function(err) {
          $('#sso-data-output').html('');
          $('<pre/>', { 'class':'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#sso-data-output');
        });
    });
  });
});
</script>
</body>
</html>
`;
