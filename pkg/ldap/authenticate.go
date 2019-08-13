package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"gopkg.in/ldap.v3"
	"os"
	"strconv"
	"strings"
)

// ErrLdapDial is returned when the service is unable to run ldap.Dial successfully.
var ErrLdapDial = errors.New("ldap-dial")

// ErrStartTLS is returned when the service is unable to run ldap.StartTLS successfully.
var ErrStartTLS = errors.New("ldap-start-tls")

// ErrLdapBind is returned when the service is unable to bind with the supplied username/password.
var ErrLdapBind = errors.New("ldap-bind")

// ErrLdapSearch is returned when the service is unable to run a search.
var ErrLdapSearch = errors.New("ldap-search")

// ErrUserNotFound is returned when the given LDAP user is not found.
var ErrUserNotFound = errors.New("user-not-found")

// ErrInvalidCreds is returned when invalid username/password is supplied.
var ErrInvalidCreds = errors.New("invalid-credentials")

// LDAPUser represents an LDAP user that has authenticated with the API.
type LDAPUser struct {
	DN           string   `json:"dn" bson:"dn"`
	CN           string   `json:"cn" bson:"cn"`
	MSID         string   `json:"msId" bson:"msId"`
	DisplayName  string   `json:"displayName" bson:"displayName"`
	GivenName    string   `json:"givenName" bson:"givenName"`
	SN           string   `json:"sn" bson:"sn"`
	Department   string   `json:"department" bson:"department"`
	Title        string   `json:"title" bson:"title"`
	Mail         string   `json:"mail" bson:"mail"`
	DepartmentID string   `json:"departmentId" bson:"departmentId"`
	MemberOf     []string `json:"memberOf" bson:"memberOf"`
}

func AuthenticateLDAP(username string, password string) (*LDAPUser, error) {
	bindCn := os.Getenv("LDAP_BIND_CN")
	bindPw := os.Getenv("LDAP_BIND_PW")
	host := os.Getenv("LDAP_HOST")
	port, _ := strconv.Atoi(os.Getenv("LDAP_PORT"))
	baseDn := os.Getenv("LDAP_BASE_DN")

	username = strings.ToLower(username)

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &LDAPUser{}, ErrLdapDial
	}
	defer l.Close()

	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return &LDAPUser{}, ErrStartTLS
	}

	err = l.Bind(bindCn, bindPw)
	if err != nil {
		return &LDAPUser{}, ErrLdapBind
	}

	searchRequest := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(cn=%s)", username),
		[]string{"dn", "cn", "displayName", "givenName", "sn", "department", "title", "mail", "uht-GLDepartmentID", "memberOf"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return &LDAPUser{}, ErrLdapSearch
	}

	if len(sr.Entries) != 1 {
		return &LDAPUser{}, ErrUserNotFound
	}

	userEntry := sr.Entries[0]
	userDn := userEntry.DN

	err = l.Bind(userDn, password)
	if err != nil {
		return &LDAPUser{}, ErrInvalidCreds
	}

	return &LDAPUser{
		DN:           userEntry.DN,
		CN:           userEntry.GetAttributeValue("cn"),
		MSID:         username,
		DisplayName:  userEntry.GetAttributeValue("displayName"),
		GivenName:    userEntry.GetAttributeValue("givenName"),
		SN:           userEntry.GetAttributeValue("sn"),
		Department:   userEntry.GetAttributeValue("department"),
		Title:        userEntry.GetAttributeValue("title"),
		Mail:         userEntry.GetAttributeValue("mail"),
		DepartmentID: userEntry.GetAttributeValue("uht-GLDepartmentID"),
		MemberOf:     userEntry.GetAttributeValues("memberOf"),
	}, nil
}
