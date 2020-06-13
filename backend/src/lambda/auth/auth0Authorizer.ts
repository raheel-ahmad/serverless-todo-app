import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
//import Axios from 'axios'
//import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJF5pdI2Uf19HwMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi0yN2lvdC15eS51cy5hdXRoMC5jb20wHhcNMjAwNjEzMTIxNzA4WhcN
MzQwMjIwMTIxNzA4WjAkMSIwIAYDVQQDExlkZXYtMjdpb3QteXkudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstKwLseYHdqGN6lh
8Rr5AQpsPyPFG0XR5aSGHJHkQxCEkoOJhqSXXt7saBRlgv1Ku/dxRGrNa7WbnZrQ
nC0pWRxEu5IL1g9RnOBMCdEupS8crHB/tYhf/cYjNI5UBIKM0gGos8HFeM3SKMYS
5t6i7oITtvNg56c7yGLFkWIbhmiU9/ofpUzjWa+uPOpXuw5x9ImyV9vjwVOyoGok
dxeATtGyUn5r69e2pZf7i1dOezPuGBCu76knVC37rmJfwhxvpYDM9nXTjs8UrjOl
kFxW46rkkPixA2wyFlJUK8XKqLdZDQb+C7+ZeC3i6ywVw9QDcE6rWGvtPuEOvSIj
HsvWAQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS8Jl2EWQ4f
sqUkViikyPuMVhKX2zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
ACRy/6T0TqP2G/4hIRtspR7kwdYR3sQ2KzHuNAl+xqfJS4nxDQKEsOgaiEyEK/YA
DYRsuXOwz11sYDeEDItyt1lhGDTpmi3cWfi4rihn+kd1+R3pJr0EYVsyKZVji6VQ
09TOSZU85pQwxDZfdyWjQu/f87I0wIC8M+ZMZgkBhoPOSVAc6f8sinL3e0BLT5b9
dg9y6s2kK4Nng08rzTZzYcYP4qwfWJ+uuWY5UX1pf9lfn9J5uYJg2FKlV9U+LwzM
+F8d1ES1szg0qC0DCaylIHzK+rXv+rc6nkcbM/uP9/6i4K52GPN2tPpKvBmgCrvW
+nt+N4Ya4r7kcbbWjPI3drI=
-----END CERTIFICATE-----`

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
//const jwksUrl = 'https://dev-4sdbcy83.auth0.com/.well-known/jwks.json'

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  //const jwt: Jwt = decode(token, { complete: true }) as Jwt
  //const jwksPayload =  Axios.get(jwksUrl)
  //const certurl =  jwksPayload['keys'][0]['x5c'][0]
  //console.log(`cert ${certurl}`)

  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
