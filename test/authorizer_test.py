import authorizer.authorizer as auth
import jwt
import pytest

###############################################
## Test fixture data
###############################################
EXAMPLE_ARN = 'arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/request'
EXAMPLE_TOKEN = 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJET190MF9ORS14LXBZVUdNeEw1S1ota1dQWU1DcXlWWUIyVzdMUmF3U1FnIn0.eyJleHAiOjE3MDI3ODA2NjQsImlhdCI6MTcwMjc3MzQ2NCwiYXV0aF90aW1lIjoxNzAyNzczNDYzLCJqdGkiOiJmODcxNjFmZi1iZTQxLTQ3ODAtYThmYi1kZjMzOTkwNDg0YWYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmFuZHJld3NsYWkuY29tL3JlYWxtcy9hbmRyZXdzbGFpIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjA5MTczMmFiLTYzNjEtNDQ3NS1iOTgyLTIyMTgzZmQ5MTRjZCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImFuZHJld3NsYWktZnJvbnRlbmQiLCJub25jZSI6IjAwMjY3MmYzLTcwNzEtNDg3MS04OTZjLTExOWE3NjdhOWY5YiIsInNlc3Npb25fc3RhdGUiOiJlMDcxOTVhMC1hMWI3LTQ1NTItYjc3Zi0xNDBlZTBiZjdmYzAiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly9jYWhlcmlhZ3VpbGFyLmFuZC5hbmRyZXdzbGFpLmNvbSIsImh0dHBzOi8vc2FoaWx0YWxraW5nY2VudHMuY29tIiwiaHR0cHM6Ly9hbmRyZXdzbGFpLmNvbSIsImh0dHBzOi8vY2FoZXJpYWd1aWxhci5jb20iXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNhaGVyaWFndWlsYXIuY29tOmFkbWluIiwib2ZmbGluZV9hY2Nlc3MiLCJ3ZWRkaW5nIiwidW1hX2F1dGhvcml6YXRpb24iLCJhbmRyZXdzbGFpLmNvbTphZG1pbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJlMDcxOTVhMC1hMWI3LTQ1NTItYjc3Zi0xNDBlZTBiZjdmYzAiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFuZHJldyBMYWkiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbmRyZXcucy5sYWk1QGdtYWlsLmNvbSIsImdpdmVuX25hbWUiOiJBbmRyZXciLCJmYW1pbHlfbmFtZSI6IkxhaSIsImVtYWlsIjoiYW5kcmV3LnMubGFpNUBnbWFpbC5jb20ifQ.Zi10SxIzEqZlZHkdkT6LHtGKI9UYBE6m7pC1calrHf2E6kUpfmoGZ3W5f58gSbmNhW0e83kAX1aLr51XuH2ssgm43sMGCnogStlsvIVv04xn9-CXXVbxCWOn3DlBz3rNdW7JJaaIxKn69D11ZgxGia8o9JllO3vSvn3w39aSGxGVKbsk7w8lGmpOrC7z4IXfVjK73sDVr1YAsJqCoxeGiyzJSpCf3zb-deNX16OF5FOxVUTwkRa38e-WFsrDoc_BVD9N0uFfhPOqvvZIyKe4pok0CZKvHPx9m8J90e5Leuey7iO5Ld8yfWM5bEGjmGAkATqCcVXs2Jk5nA1wHER3fQ'
PARSED_TOKEN = {'exp': 1702780664,
                'iat': 1702773464,
                'auth_time': 1702773463,
                'jti': 'f87161ff-be41-4780-a8fb-df33990484af',
                'iss': 'https://keycloak.andrewslai.com/realms/andrewslai',
                'aud': 'account',
                'sub': '091732ab-6361-4475-b982-22183fd914cd',
                'typ': 'Bearer',
                'azp': 'andrewslai-frontend',
                'nonce': '002672f3-7071-4871-896c-119a767a9f9b',
                'session_state': 'e07195a0-a1b7-4552-b77f-140ee0bf7fc0',
                'allowed-origins': ['https://caheriaguilar.and.andrewslai.com',
                                    'https://sahiltalkingcents.com',
                                    'https://andrewslai.com',
                                    'https://caheriaguilar.com'],
                'realm_access': {'roles': ['caheriaguilar.com:admin',
                                           'offline_access',
                                           'wedding',
                                           'uma_authorization',
                                           'andrewslai.com:admin']},
                'resource_access': {'account': {'roles': ['manage-account',
                                                          'manage-account-links',
                                                          'view-profile']}},
                'scope': 'openid profile email',
                'sid': 'e07195a0-a1b7-4552-b77f-140ee0bf7fc0',
                'email_verified': True,
                'name': 'Andrew Lai',
                'preferred_username': 'andrew.s.lai5@gmail.com',
                'given_name': 'Andrew',
                'family_name': 'Lai',
                'email': 'andrew.s.lai5@gmail.com'}

# Validate against a live Keycloak instance
# auth.validate_token_signature(EXAMPLE_TOKEN)
# auth.validate_token_signature(EXAMPLE_TOKEN + 'x')

###############################################
## Tests
###############################################
def test_parse_method_arn():
    assert {
        'apiId':     'abcdef123',
        'stage':     'test',
        'accountId': '123456789012',
        'region':    'us-east-1'
    } == auth.parse_method_arn(EXAMPLE_ARN)


class TestLambdaHandler:
    def test_happy_path(self):
        assert {
            'principalId'    : 'user|andrew.s.lai5@gmail.com|e07195a0-a1b7-4552-b77f-140ee0bf7fc0',
            'context'        : {'key': 'value',},
            'policyDocument' : {'Statement' : [{'Action'   : 'execute-api:Invoke',
                                                'Effect'   : 'Allow',
                                                'Resource' : ['arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/*/*']}],
                                'Version'   : '2012-10-17'}
        } == auth.lambda_handler({'methodArn': EXAMPLE_ARN,
                                  'authorizationToken': EXAMPLE_TOKEN,
                                  'ENV': 'test',
                                  'TOKEN': PARSED_TOKEN},
                                 {})
        pass


    def test_malformed_token(self):
        with pytest.raises(Exception):
            auth.lambda_handler({'methodArn': EXAMPLE_ARN,
                                 'authorizationToken': 'NOT Bearer XXXX',
                                 'ENV': 'test',
                                 'TOKEN': {
                                     'exp': 1702780664,
                                     'iat': 1702773464,
                                     'auth_time': 1702773463,
                                     'realm_access': {'roles': ['caheriaguilar.com:admin',
                                                                'andrewslai.com:admin']},
                                     'email': 'andrew.s.lai5@gmail.com'}},
                                {})
        pass

    def test_invalid_role(self):
        with pytest.raises(Exception):
            auth.lambda_handler({'methodArn': EXAMPLE_ARN,
                                 'authorizationToken': EXAMPLE_TOKEN,
                                 'ENV': 'test',
                                 'TOKEN': {
                                     'exp': 1702780664,
                                     'iat': 1702773464,
                                     'auth_time': 1702773463,
                                     'realm_access': {'roles': ['caheriaguilar.com:admin',]},
                                     'email': 'andrew.s.lai5@gmail.com'}},
                                {})
        pass
