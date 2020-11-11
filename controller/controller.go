package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/cemenson/basic-go-jwt-auth/model"
)

var cacher *redis.Client
var storer *mongo.Client
var accountsCol *mongo.Collection

func init() {
	os.Setenv("REGIST_HOST", "localhost:6379")
	os.Setenv("REFRESH_SECRET", "zyxwvutsrqponmlk")
	os.Setenv("ACCESS_SECRET", "abcdefghijklmnop")
	os.Setenv("MONGO_HOST", "mongodb://localhost:27017")

	cacher = redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_HOST"),
	})

	_, cErr := cacher.Ping().Result()
	if cErr != nil {
		panic(cErr)
	}

	storer, sErr := mongo.Connect(context.TODO(),
		options.Client().ApplyURI(os.Getenv("MONGO_HOST")))
	if sErr != nil {
		log.Fatal(sErr)
	}
	if connErr := storer.Ping(context.TODO(), nil); connErr != nil {
		log.Fatal(connErr)
	}
	accountsCol = storer.Database("accounts").Collection("accounts")
}

// LoginHandler processes the login requests.
// Called with POST method.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var account model.Account

	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &account); err != nil {
		log.Fatal(err)
	}

	var usr model.Account
	if getErr := accountsCol.FindOne(context.TODO(),
		bson.D{
			primitive.E{
				Key:   "_id",
				Value: account.ID,
			},
		},
	).Decode(&usr); getErr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	valid, passErr := validatePassword(account)
	if passErr != nil || !valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := createToken(account.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := createAuth(account.ID, token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
	})
}

// LogoutHandler processes the logout requests.
// Called with POST method.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tokenMeta, err := extractTokenMetadata(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	result, delErr := deleteAuth(tokenMeta.AccessID)
	if delErr != nil || result == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RegisterHandler processes the registration requests.
// Called with POST method.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var account model.Account

	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &account); err != nil {
		log.Fatal(err)
	}

	hashPassword(&account)
	_, insErr := accountsCol.InsertOne(context.TODO(), account)
	if insErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// @todo: Generate email validation guid
	// @todo: Send email for validation
	// @todo: Add job to queue for validation timeout

	w.WriteHeader(http.StatusOK)
}

func hashPassword(acc *model.Account) error {
	acc.Salt = strconv.FormatInt(time.Now().Unix(), 10)
	hash := sha256.Sum256([]byte(acc.Salt + acc.Password))
	acc.Password = string(hash[:])

	return nil
}

func validatePassword(account model.Account) (bool, error) {
	var usr model.Account
	if getErr := accountsCol.FindOne(context.TODO(),
		bson.D{
			primitive.E{
				Key:   "_id",
				Value: account.ID,
			},
		},
	).Decode(&usr); getErr != nil {
		return false, getErr
	}
	hash := sha256.Sum256([]byte(usr.Salt + account.Password))

	if string(hash[:]) == usr.Password {
		return true, nil
	}

	return false, nil
}

// AccountHandler processes the registration requests.
// Called with GET method.
func AccountHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tokenMeta, err := extractTokenMetadata(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	}
	id, err := fetchAuth(tokenMeta)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	}

	println(id)
	w.WriteHeader(http.StatusOK)
}

// RefreshTokenHandler processes the refreshing of tokens.
// Called with POST method.
func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var tokenMap map[string]string

	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &tokenMap); err != nil {
		log.Fatal(err)
	}

	token, err := jwt.Parse(tokenMap["refresh_token"],
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil,
					fmt.Errorf("unexpected signing method: %v",
						token.Header["alg"])
			}
			return []byte(os.Getenv("REFRESH_SECRET")), nil
		})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUUID, ok := claims["refresh_id"].(string)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		id, ok := claims["id"].(string)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		result, delErr := deleteAuth(refreshUUID)
		if delErr != nil || result == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		renToken, crErr := createToken(id)
		if crErr != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if saveErr := createAuth(id, renToken); saveErr != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"access_token":  renToken.AccessToken,
			"refresh_token": renToken.RefreshToken,
		})
		return
	}
	w.WriteHeader(http.StatusUnauthorized)

}

// TokenValidate is a middleware for token validation
// per request served.
func TokenValidate(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if err := validateToken(r); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
}

func extractTokenMetadata(r *http.Request) (*model.AccessDetails, error) {
	token, err := verifyToken(r)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessID, ok := claims["access_id"].(string)
		if !ok {
			return nil, err
		}
		id, ok := claims["id"].(string)
		if !ok {
			return nil, err
		}
		return &model.AccessDetails{
			AccessID: accessID,
			ID:       id,
		}, nil
	}
	return nil, err
}

func fetchAuth(ad *model.AccessDetails) (string, error) {
	id, err := cacher.Get(ad.AccessID).Result()
	if err != nil {
		return "", err
	}
	return id, nil
}

func createAuth(id string, token *model.TokenDetails) error {
	accExp := time.Unix(token.AccExp, 0)
	refExp := time.Unix(token.RefExp, 0)
	now := time.Now()

	if accErr := cacher.Set(token.AccessUUID, id,
		accExp.Sub(now)).Err(); accErr != nil {
		return accErr
	}
	if refErr := cacher.Set(token.RefreshUUID, id,
		refExp.Sub(now)).Err(); refErr != nil {
		return refErr
	}
	return nil
}

func deleteAuth(accessID string) (int64, error) {
	result, err := cacher.Del(accessID).Result()
	if err != nil {
		return 0, err
	}
	return result, nil
}

func createToken(accountID string) (*model.TokenDetails, error) {
	tokenRecord := &model.TokenDetails{
		AccExp:      time.Now().Add(time.Minute * 15).Unix(),
		AccessUUID:  uuid.New().String(),
		RefExp:      time.Now().Add(time.Hour * 24 * 7).Unix(),
		RefreshUUID: uuid.New().String(),
	}

	accToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"id":         accountID,
			"authorised": true,
			"expire":     tokenRecord.AccExp,
			"access_id":  tokenRecord.AccessUUID,
		})

	aT, err := accToken.SignedString(
		[]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	tokenRecord.AccessToken = aT

	refToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"refresh_id": tokenRecord.RefreshUUID,
			"id":         accountID,
			"expire":     tokenRecord.RefExp,
		})

	rT, err := refToken.SignedString(
		[]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	tokenRecord.RefreshToken = rT

	return tokenRecord, nil
}

func validateToken(r *http.Request) error {
	token, err := verifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func verifyToken(r *http.Request) (*jwt.Token, error) {
	rawToken := extractToken(r)
	token, err := jwt.Parse(rawToken,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil,
					fmt.Errorf("unexpected signing method: %v",
						token.Header["alg"])
			}
			return []byte(os.Getenv("ACCESS_SECRET")), nil
		})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func extractToken(r *http.Request) string {
	bToken := r.Header.Get("Authorization")
	if strArr := strings.Split(bToken, " "); len(strArr) == 2 {
		return strArr[1]
	}
	return bToken
}
