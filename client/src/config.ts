// TODO: Once your application is deployed, copy an API id here so that the frontend could interact with it
const apiId = 'new3k2ctd2'
export const apiEndpoint = `https://${apiId}.execute-api.us-west-2.amazonaws.com/dev`

export const authConfig = {
  // TODO: Create an Auth0 application and copy values from it into this map
  domain: 'dev-27iot-yy.us.auth0.com',            // Auth0 domain
  clientId: 'e5BwFwVbjHA7MkSYXlbI8AEiFXJGDbGx',          // Auth0 client id
  callbackUrl: 'http://localhost:3000/callback'
}
