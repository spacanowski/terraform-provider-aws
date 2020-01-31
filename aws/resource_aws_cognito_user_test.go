package aws

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func TestAccAWSCognitoUser_basic(t *testing.T) {
	poolName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	username := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(150, acctest.CharSetAlphaNum))
	updatedUsername := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resourceName := "aws_cognito_user.admin"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t); testAccPreCheckAWSCognitoIdentityProvider(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSCognitoUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSCognitoUserConfig_basic(poolName, username),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSCognitoUserExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "username", username),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccAWSCognitoUserConfig_basic(poolName, updatedUsername),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSCognitoUserExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "username", updatedUsername),
				),
			},
		},
	})
}

func TestAccAWSCognitoUser_complex(t *testing.T) {
	poolName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	username := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	updatedUsername := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resourceName := "aws_cognito_user.admin"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t); testAccPreCheckAWSCognitoIdentityProvider(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSCognitoUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSCognitoUserConfig_complex(poolName, username, "This is the user group description", 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSCognitoUserExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "description", "This is the user group description"),
					resource.TestCheckResourceAttr(resourceName, "precedence", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "role_arn"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccAWSCognitoUserConfig_complex(poolName, updatedUsername, "This is the updated user group description", 42),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSCognitoUserExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "username", updatedUsername),
					resource.TestCheckResourceAttr(resourceName, "description", "This is the updated user group description"),
					resource.TestCheckResourceAttr(resourceName, "precedence", "42"),
					resource.TestCheckResourceAttrSet(resourceName, "role_arn"),
				),
			},
		},
	})
}

func TestAccAWSCognitoUser_RoleArn(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc")
	resourceName := "aws_cognito_user.main"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t); testAccPreCheckAWSCognitoIdentityProvider(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSCognitoUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSCognitoUserConfig_RoleArn(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSCognitoUserExists(resourceName),
					resource.TestCheckResourceAttrSet(resourceName, "role_arn"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccAWSCognitoUserConfig_RoleArn_Updated(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAWSCognitoUserExists(resourceName),
					resource.TestCheckResourceAttrSet(resourceName, "role_arn"),
				),
			},
		},
	})
}

func testAccCheckAWSCognitoUserExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		id := rs.Primary.ID
		name := rs.Primary.Attributes["username"]
		userPoolId := rs.Primary.Attributes["user_pool_id"]

		if name == "" {
			return errors.New("No Cognito User Name set")
		}

		if userPoolId == "" {
			return errors.New("No Cognito User Pool Id set")
		}

		if id != fmt.Sprintf("%s/%s", userPoolId, name) {
			return fmt.Errorf(fmt.Sprintf("ID should be user_pool_id/name. ID was %s. name was %s, user_pool_id was %s", id, name, userPoolId))
		}

		conn := testAccProvider.Meta().(*AWSClient).cognitoidpconn

		params := &cognitoidentityprovider.AdminGetUserInput{
			Username:   aws.String(rs.Primary.Attributes["username"]),
			UserPoolId: aws.String(rs.Primary.Attributes["user_pool_id"]),
		}

		_, err := conn.AdminGetUser(params)
		return err
	}
}

func testAccCheckAWSCognitoUserDestroy(s *terraform.State) error {
	conn := testAccProvider.Meta().(*AWSClient).cognitoidpconn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_cognito_user" {
			continue
		}

		params := &cognitoidentityprovider.AdminGetUserInput{
			Username:   aws.String(rs.Primary.ID),
			UserPoolId: aws.String(rs.Primary.Attributes["user_pool_id"]),
		}

		_, err := conn.AdminGetUser(params)

		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ResourceNotFoundException" {
				return nil
			}
			return err
		}
	}

	return nil
}

func testAccAWSCognitoUserConfig_basic(poolName, username string) string {
	return fmt.Sprintf(`
resource "aws_cognito_user_pool" "main" {
  name = "%s"
}

resource "aws_cognito_user" "main" {
  username     = "%s"
  user_pool_id = "${aws_cognito_user_pool.main.id}"
}
`, poolName, username)
}

func testAccAWSCognitoUserConfig_complex(poolName, username, groupDescription string, precedence int) string {
	return fmt.Sprintf(`
resource "aws_cognito_user_pool" "main" {
  name = "%s"
}

resource "aws_iam_role" "group_role" {
  name = "%s"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "us-east-1:12345678-dead-beef-cafe-123456790ab"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_cognito_user_group" "main" {
  name         = "%s"
  user_pool_id = "${aws_cognito_user_pool.main.id}"
  description  = "%s"
  precedence   = %v
  role_arn     = "${aws_iam_role.group_role.arn}"
}
`, poolName, username, username, groupDescription, precedence)
}

func testAccAWSCognitoUserConfig_RoleArn(rName string) string {
	return fmt.Sprintf(`
resource "aws_cognito_user_pool" "main" {
  name = "%[1]s"
}

resource "aws_iam_role" "group_role" {
  name = "%[1]s"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity"
    }
  ]
}
EOF
}

resource "aws_cognito_user_group" "main" {
  name         = "%[1]s"
  user_pool_id = "${aws_cognito_user_pool.main.id}"
  role_arn     = "${aws_iam_role.group_role.arn}"
}
`, rName)
}

func testAccAWSCognitoUserConfig_RoleArn_Updated(rName string) string {
	return fmt.Sprintf(`
resource "aws_cognito_user_pool" "main" {
  name = "%[1]s"
}

resource "aws_iam_role" "group_role_updated" {
  name = "%[1]s-updated"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity"
    }
  ]
}
EOF
}

resource "aws_cognito_user_group" "main" {
  name         = "%[1]s"
  user_pool_id = "${aws_cognito_user_pool.main.id}"
  role_arn     = "${aws_iam_role.group_role_updated.arn}"
}
`, rName)
}
