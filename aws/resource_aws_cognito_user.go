package aws

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

func resourceAwsCognitoUser() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsCognitoUserCreate,
		Read:   resourceAwsCognitoUserRead,
		Update: resourceAwsCognitoUserUpdate,
		Delete: resourceAwsCognitoUserDelete,

		Importer: &schema.ResourceImporter{
			State: resourceAwsCognitoUserImport,
		},

		// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html
		Schema: map[string]*schema.Schema{
			"username": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validateCognitoUserUsername,
			},
			"user_pool_id": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validateCognitoUserPoolId,
			},
			"temporary_password": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"permanent_password"},
				ValidateFunc:  validateCognitoUserPassword,
			},
			"permanent_password": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"temporary_password"},
				ValidateFunc:  validateCognitoUserPassword,
			},
			"message_action": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateFunc: validation.StringInSlice([]string{
					"RESEND",
					"SUPPRESS",
				}, false),
			},
			"force_alias_creation": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"desired_delivery_mediums": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{
						"SMS",
						"EMAIL",
					}, false),
				},
			},
			"client_metadata": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"validation_data": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     true,
							ValidateFunc: validateAttributeTypeName,
						},
						"value": {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     true,
							ValidateFunc: validation.StringLenBetween(0, 2048),
						},
					},
				},
			},
			"user_attributes": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     true,
							ValidateFunc: validateAttributeTypeName,
						},
						"value": {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     true,
							ValidateFunc: validation.StringLenBetween(0, 2048),
						},
					},
				},
			},
			"groups": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"enabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"user_status": {
				Type:     schema.TypeBool,
				Computed: true,
			},
		},
	}
}

func resourceAwsCognitoUserCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).cognitoidpconn

	params := &cognitoidentityprovider.AdminCreateUserInput{
		Username:   aws.String(d.Get("username").(string)),
		UserPoolId: aws.String(d.Get("user_pool_id").(string)),
	}

	if v, ok := d.GetOk("temporary_password"); ok {
		params.TemporaryPassword = aws.String(v.(string))
	}

	if v, ok := d.GetOk("message_action"); ok {
		params.MessageAction = aws.String(v.(string))
	}

	if v, ok := d.GetOk("force_alias_creation"); ok {
		params.ForceAliasCreation = aws.Bool(v.(bool))
	}

	if v, ok := d.GetOk("desired_delivery_mediums"); ok {
		params.DesiredDeliveryMediums = expandStringList(v.(*schema.Set).List())
	}

	if cm, ok := d.GetOk("client_metadata"); ok {
		clientMetadata := make(map[string]string)
		for k, v := range cm.(map[string]interface{}) {
			clientMetadata[k] = v.(string)
		}

		if len(clientMetadata) > 0 {
			params.ClientMetadata = aws.StringMap(clientMetadata)
		}
	}

	if v, ok := d.GetOk("validation_data"); ok {
		params.ValidationData = expandCognitoUserAttributes(v.(*schema.Set).List())
	}

	if v, ok := d.GetOk("user_attributes"); ok {
		params.UserAttributes = expandCognitoUserAttributes(v.(*schema.Set).List())
	}

	log.Print("[DEBUG] Creating Cognito User")

	resp, err := conn.AdminCreateUser(params)
	if err != nil {
		return fmt.Errorf("Error creating Cognito User: %s", err)
	}

	if g, ok := d.GetOk("groups"); ok {
		for _, v := range g.([]string) {
			if err := addUserToGroup(conn, d, v); err != nil {
				return err
			}
		}
	}

	if v, ok := d.GetOk("permanent_password"); ok {
		log.Print("[DEBUG] Setting Cognito User permanent password")

		psswdParams := &cognitoidentityprovider.AdminSetUserPasswordInput{
			Username:   aws.String(d.Get("username").(string)),
			UserPoolId: aws.String(d.Get("user_pool_id").(string)),
			Password:   aws.String(v.(string)),
			Permanent:  aws.Bool(true),
		}

		_, err := conn.AdminSetUserPassword(psswdParams)
		if err != nil {
			return fmt.Errorf("Error setting Cognito User permanent password: %s", err)
		}

		log.Print("[DEBUG] Set Cognito User permanent password")
	}

	d.SetId(fmt.Sprintf("%s/%s", d.Get("user_pool_id").(string), *resp.User.Username))

	return resourceAwsCognitoUserRead(d, meta)
}

func resourceAwsCognitoUserRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).cognitoidpconn

	params := &cognitoidentityprovider.AdminGetUserInput{
		Username:   aws.String(d.Get("username").(string)),
		UserPoolId: aws.String(d.Get("user_pool_id").(string)),
	}

	log.Print("[DEBUG] Reading Cognito User")

	resp, err := conn.AdminGetUser(params)
	if err != nil {
		if isAWSErr(err, "ResourceNotFoundException", "") {
			log.Printf("[WARN] Cognito User %s is already gone", d.Id())
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error reading Cognito User: %s", err)
	}

	userAttributes := make([]map[string]string, len(resp.UserAttributes))
	for _, v := range resp.UserAttributes {
		m := make(map[string]string)
		m["name"] = *v.Name
		m["value"] = *v.Value
		userAttributes = append(userAttributes, m)
	}

	d.Set("user_attributes", userAttributes)
	d.Set("enabled", resp.Enabled)
	d.Set("user_status", resp.UserStatus)

	groupsParams := &cognitoidentityprovider.AdminListGroupsForUserInput{
		Username:   aws.String(d.Get("username").(string)),
		UserPoolId: aws.String(d.Get("user_pool_id").(string)),
	}

	groupsResp, err := conn.AdminListGroupsForUser(groupsParams)
	if err != nil {
		log.Print("[DEBUG] Could not get Cognito User groups", err)
	} else {
		groups := make([]string, len(groupsResp.Groups))
		for _, v := range groupsResp.Groups {
			groups = append(groups, *v.GroupName)
		}
		d.Set("groups", groups)
	}

	return nil
}

func resourceAwsCognitoUserUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).cognitoidpconn

	params := &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		Username:   aws.String(d.Get("name").(string)),
		UserPoolId: aws.String(d.Get("user_pool_id").(string)),
	}

	if d.HasChange("user_attributes") {
		params.UserAttributes = expandCognitoUserAttributes(d.Get("user_attributes").(*schema.Set).List())
	}

	if d.HasChange("groups") {
		o, n := d.GetChange("groups")

		for _, v := range n.([]string) {
			if contains(o.([]string), v) {
				continue
			}
			log.Print("[DEBUG] Adding Cognito User to group", v)

			groupParams := &cognitoidentityprovider.AdminAddUserToGroupInput{
				Username:   aws.String(d.Get("username").(string)),
				UserPoolId: aws.String(d.Get("user_pool_id").(string)),
				GroupName:  aws.String(v),
			}

			_, err := conn.AdminAddUserToGroup(groupParams)
			if err != nil {
				return fmt.Errorf("Error adding Cognito User to group: %s", err)
			}

			log.Print("[DEBUG] Added Cognito User to group", v)
		}

		for _, v := range o.([]string) {
			if contains(n.([]string), v) {
				continue
			}
			if err := addUserToGroup(conn, d, v); err != nil {
				return err
			}
		}
	}

	log.Print("[DEBUG] Updating Cognito User")

	_, err := conn.AdminUpdateUserAttributes(params)
	if err != nil {
		return fmt.Errorf("Error updating Cognito User: %s", err)
	}

	return resourceAwsCognitoUserRead(d, meta)
}

func resourceAwsCognitoUserDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).cognitoidpconn

	params := &cognitoidentityprovider.AdminDeleteUserInput{
		Username:   aws.String(d.Get("username").(string)),
		UserPoolId: aws.String(d.Get("user_pool_id").(string)),
	}

	log.Print("[DEBUG] Deleting Cognito User")

	_, err := conn.AdminDeleteUser(params)
	if err != nil {
		return fmt.Errorf("Error deleting Cognito User: %s", err)
	}

	return nil
}

func resourceAwsCognitoUserImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	idSplit := strings.Split(d.Id(), "/")
	if len(idSplit) != 2 {
		return nil, errors.New("Error importing Cognito User. Must specify user_pool_id/username")
	}
	userPoolId := idSplit[0]
	name := idSplit[1]
	d.Set("user_pool_id", userPoolId)
	d.Set("username", name)
	return []*schema.ResourceData{d}, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func addUserToGroup(conn *cognitoidentityprovider.CognitoIdentityProvider, d *schema.ResourceData, g string) error {
	log.Print("[DEBUG] Adding Cognito User to group", g)

	groupParams := &cognitoidentityprovider.AdminAddUserToGroupInput{
		Username:   aws.String(d.Get("username").(string)),
		UserPoolId: aws.String(d.Get("user_pool_id").(string)),
		GroupName:  aws.String(g),
	}

	_, err := conn.AdminAddUserToGroup(groupParams)
	if err != nil {
		return fmt.Errorf("Error adding Cognito User to group: %s", err)
	}

	log.Print("[DEBUG] Added Cognito User to group", g)

	return nil
}
