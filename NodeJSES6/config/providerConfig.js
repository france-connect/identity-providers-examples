import config from './configManager';

module.exports.provider = {
    scopes: ['birth'],
    cookies: {
      long: {signed: true, maxAge: (1 * 24 * 60 * 60) * 1000}, // 1 day in ms
      short: {signed: true},
      keys: ['some secret key', 'and also the old rotated away some time ago', 'and one more'],
    },
    claims: {
      family_name: ['family_name'],
      given_name: ['given_name'],
      nickname: ['nickname'],
      gender: ['gender'],
      preferred_username: ['preferred_username'],
      address: ['address'],
      email: ['email'],
      siren: ['siren'],
      organizational_unit: ['organizational_unit'],
      identity_provider: ['identity_provider'],
      birth: ['birthcountry', 'birthplace'],
      profile: [
        'name',
        'family_name',
        'given_name',
        'nickname',
        'gender',
        'preferred_username',
        'email',
        'siren',
        'birthdate',
        'organizational_unit',
        'identity_provider'
      ],
    },
    grant_types_supported: ['authorization_code'],
    features: {
      devInteractions: false,
      discovery: true,
      sessionManagement: true,
      backchannelLogout: true,
      claimsParameter: true,
    },
    routes: {
      authorization: '/user/authorize',
      end_session: '/user/session/end',
      revocation: '/user/token/revocation',
      token: '/user/token',
      userinfo: '/api/user',
    },
    formats: {
      default: 'opaque',
    },
    interactionUrl: function interactionUrl(ctx, interaction) { // eslint-disable-line no-unused-vars
      return `/interaction/${ctx.oidc.uuid}`;
    },
    async logoutSource(ctx, form)
    {
      console.log(this.oidc.params)
      if (this.oidc.params.post_logout_redirect_uri) {
        this.body = `<!DOCTYPE html>
      <head>
        <title>Logout</title>
      </head>
      <body>
        ${form}
        <script>
          var form = document.forms[0];
          var input = document.createElement('input');
          input.type = 'hidden';
          input.name = 'logout';
          input.value = 'yes';
    
          form.appendChild(input);
    
          form.submit();
        </script>
      </body>
      </html>`;
      } else {
        this.body = `<!DOCTYPE html>
      <head>
        <title>Logout</title>
      </head>
      <body>
        ${form}
        Do you want to logout from the OP?
        <button type="submit" form="op.logoutForm" name="logout" value="yes">Yes</button>
        <button type="submit" form="op.logoutForm">Please don't!</button>
      </body>
      </html>`;
      }
},
  clientCacheDuration: 1 * 24 * 60 * 60, // 1 day in seconds,
  ttl: {
    AccessToken: 1 * 60 * 60, // 1 hour in seconds
    AuthorizationCode: 10 * 60, // 10 minutes in seconds
    IdToken: 1 * 60 * 60, // 1 hour in seconds
    DeviceCode: 10 * 60, // 10 minutes in seconds
    RefreshToken: 1 * 24 * 60 * 60, // 1 day in seconds
  },
};

module.exports.clients = [{ ...config }];
