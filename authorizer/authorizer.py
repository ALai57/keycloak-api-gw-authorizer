import re
import jwt
import requests

KEYCLOAK_OIDC_URL = 'https://keycloak.andrewslai.com/realms/andrewslai/.well-known/openid-configuration'

# The methodArn is of the form `arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/request`
def parse_method_arn(methodArn):
    tmp = methodArn.split(':')

    # API Gateway information
    apiGatewayArnTmp = tmp[5].split('/')

    return {
        'apiId': apiGatewayArnTmp[0],
        'stage': apiGatewayArnTmp[1],

        'accountId': tmp[4],
        'region': tmp[3]
    }

def validate_token_signature(id_token):
    # https://pyjwt.readthedocs.io/en/stable/usage.html#retrieve-rsa-signing-keys-from-a-jwks-endpoint
    # Per docs above: Expiration time is automatically verified in jwt.decode() and raises
    # jwt.ExpiredSignatureError if the expiration time is in the past:
    oidc_config = requests.get(KEYCLOAK_OIDC_URL).json()
    signing_algos = oidc_config["id_token_signing_alg_values_supported"]
    jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    return jwt.decode(id_token, key=signing_key.key, algorithms=signing_algos, audience='account')

def validate_claims(token):
    ## Issued at
    ## etc
    pass


def lambda_handler(event, context):
    encoded_token = event['authorizationToken']
    print('Attempting to decode token')

    try:
        decoded_token = validate_token_signature(encoded_token) if event.get('ENV') != 'test' else event.get('TOKEN')

        validate_claims(decoded_token)

        # Build policy
        roles = decoded_token.get('realm_access').get('roles')
        if roles and ('andrewslai.com:admin' in roles):
            print('Found roles')
            config = parse_method_arn(event['methodArn'])
            policy = AuthPolicy(f"user|{decoded_token.get('email')}|{decoded_token.get('sid')}", config)
            policy.allowAllMethods()
            #policy.allowMethod(HttpVerb.GET, '/pets/*')
            return policy.build({'key': 'value',})
        else:
            print(f"No roles associated with user: {decoded_token.get('email')}")
            raise Exception('Unauthorized')

    except Exception as ex:
        print('Unable to decode token')
        raise ex




class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'


class AuthPolicy(object):
    awsAccountId = ''
    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ''
    version = '2012-10-17'
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    '''Internal lists of allowed and denied methods.

    These are lists of objects and each object has 2 properties: A resource
    ARN and a nullable conditions statement. The build method processes these
    lists and generates the approriate statements for the final policy.
    '''
    allowMethods = []
    denyMethods = []

    apiId = "<<apiId>>"
    region = "<<region>>"
    stage = "<<stage>>"

    def __init__(self, principal, config):
        self.awsAccountId = config['accountId']
        self.apiId = config['apiId']
        self.region = config['region']
        self.stage = config['stage']
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        '''Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.'''
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.apiId, self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, conditions)

    def build(self, context):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'context':     context,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy
