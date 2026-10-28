# Auth0 Authentication API Debugger Extension

This extension allows you to test and debug the various Authentication API endpoints. See the [documentation](https://auth0.com/docs/customize/extensions/authentication-api-debugger-extension) for more information.

## Running in Development

Copy the example configuration file and update it with your tenant domain:

```bash
cp ./server/config.example.json ./server/config.json
```

```json
{
  "AUTH0_DOMAIN": "me.auth0.com",
  "AUTH0_RTA": "https://auth0.auth0.com",
  "PORT": 3000
}
```

Then you can run the extension:

```bash
npm install
npm run serve:dev
```

## Running the Tests

```bash
npm test
```

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
