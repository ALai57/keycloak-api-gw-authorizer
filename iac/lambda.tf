locals {
  function_name="keycloak-api-gateway-authorizer"
}

resource "aws_lambda_function" "authorizer" {
  filename      = "../dist/keycloak-authorizer.zip"
  function_name = local.function_name
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "authorizer.lambda_handler"

  source_code_hash = filebase64sha256("../dist/keycloak-authorizer.zip") #data.archive_file.lambda.output_base64sha256

  runtime = "python3.10"
  depends_on = [aws_iam_role.iam_for_lambda, aws_cloudwatch_log_group.function_log_group]
}


data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_lambda_permission" "apigw_authorizer" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"

  # The /*/* portion grants access from any method on any resource
  # within any API gateway. This allows the Authorizer to be used
  # by any API GW.
  source_arn = "arn:aws:execute-api:us-east-1:758589815425:*/*/*"
}

#######################################################
## Logging
#######################################################
resource "aws_cloudwatch_log_group" "function_log_group" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 7
  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_iam_policy" "function_logging_policy" {
  name   = "function-logging-policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        Action : [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Effect : "Allow",
        Resource : "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "function_logging_policy_attachment" {
  role = aws_iam_role.iam_for_lambda.id
  policy_arn = aws_iam_policy.function_logging_policy.arn
}
