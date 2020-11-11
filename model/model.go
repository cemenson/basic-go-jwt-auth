package model

// Account model
type Account struct {
	ID       string `json:"id" bson:"_id"`
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
	Salt     string `json:"salt" bson:"salt"`
}

// TokenDetails model
type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
	AccExp       int64
	RefExp       int64
}

// AccessDetails model
type AccessDetails struct {
	AccessID string
	ID       string
}
