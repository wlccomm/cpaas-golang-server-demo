package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func main() {

	// add first user
	var user User
	user.Username = "glownes@whitelabelcomm.com"
	user.Password = "password123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Failed to hash password")
		panic(0)
	}
	user.Password = string(hashedPassword)
	user.ID = uint(len(users) + 1)
	users = append(users, user)

	r := gin.Default()
	r.Use(cors.Default())

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	// r.POST("/register", register)
	r.POST("/login", login)
	r.GET("/protected", AuthMiddleware(), protected)
	r.Run() // listen and serve on 0.0.0.0:8080
}

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var users = []User{}

// var jwtKey = []byte(os.Getenv("JWT_SECRET"))
var jwtKey = []byte("gregwashere")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// func register(c *gin.Context) {
// 	var user User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}

// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
// 		return
// 	}

// 	user.Password = string(hashedPassword)
// 	user.ID = uint(len(users) + 1)
// 	users = append(users, user)

// 	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully", "user": user})
// }

func login(c *gin.Context) {
	var inputUser User
	if err := c.ShouldBindJSON(&inputUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	spew.Dump(inputUser)

	var storedUser *User
	for _, user := range users {
		if user.Username == inputUser.Username {
			storedUser = &user
			break
		}
	}

	if storedUser == nil || bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(inputUser.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: inputUser.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	fmt.Println(tokenString)
	spew.Dump(tokenString)

	// test
	claimsOutput := &Claims{}
	tokenOutput, err := jwt.ParseWithClaims(tokenString, claimsOutput, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	fmt.Println(err)
	fmt.Println(tokenOutput)
	spew.Dump(tokenOutput)

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func protected(c *gin.Context) {

	var username string
	returnAny, exists := c.Get("auth_username")
	if exists && returnAny != nil {
		username = returnAny.(string)
	}
	spew.Dump(username)

	c.JSON(http.StatusOK, gin.H{"message": "Protected endpoint accessed successfully for " + username})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			fmt.Println("error: tokenString = ''")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			fmt.Println("error with ParseWithClaims")
			spew.Dump(err)
			spew.Dump(token)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		fmt.Println("middleware ok:")
		spew.Dump(claims)
		spew.Dump(token)

		c.Set("auth_username", claims.Username)

		c.Next()
	}
}
