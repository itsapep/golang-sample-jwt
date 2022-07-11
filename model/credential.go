package model

type Credential struct {
	Username string `json:"userName"`
	Password string `json:"userPassword"`
	Email    string
}
