package model

type TokenDetails struct {
	AccessToken string
	AccessUUID  string
	AtExpires   int64
}

type AccessDetails struct {
	AccessUUID string
	Username   string
}
