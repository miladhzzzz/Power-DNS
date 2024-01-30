package controllers

//import (
//	"context"
//	"fmt"
//	"github.com/gin-gonic/gin"
//	"net/http"
//	"time"
//)
//
////var (
////	conf                  *oauth2.Config
////	state                 string
////	users                 *models.UserInput
////	repos                 *models.Repos
////	mySuperSecretPassword = "unicornsAreAwesome"
////	cnf, _                = config.ReadConfig()
////)
//
//type AuthController struct {
//	authService   services.AuthService
//	githubService services.GithubService
//	//userService services.UserService
//	ctx        context.Context
//	collection *mongo.Collection
//}
//
//func NewAuthController(authService services.AuthService, ctx context.Context, githubService services.GithubService, collection *mongo.Collection) AuthController {
//	return AuthController{authService: authService, githubService: githubService, ctx: ctx}
//}
//
//func (ac *AuthController) Cli() gin.HandlerFunc {
//	return func(c *gin.Context) {
//		var req *models.CliReq
//
//		err := c.BindJSON(&req)
//		if err != nil {
//			return
//		}
//
//		ac.authService.CliLogin(req)
//	}
//
//}
//
//func (ac *AuthController) Auth() gin.HandlerFunc {
//
//	return func(ctx *gin.Context) {
//
//		gitCode := ctx.Query("code")
//		idempotencyID := ctx.Query("state")
//
//		if ctx.Request.Header.Get("Authorization") == "" && gitCode == "" {
//			ctx.AbortWithStatus(http.StatusUnauthorized)
//			return
//		}
//
//		if ctx.Request.Header.Get("Authorization") != "" {
//			_, err := request.ParseFromRequest(ctx.Request, request.OAuth2Extractor, func(token *jwtlib.Token) (interface{}, error) {
//				b := []byte(mySuperSecretPassword)
//				return b, nil
//			})
//
//			if err != nil {
//				ctx.AbortWithError(401, err)
//				return
//			}
//		}
//
//		if gitCode != "" {
//			tok, err := conf.Exchange(context.Background(), ctx.Query("code"))
//			if err != nil {
//				ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to do exchange: %v", err))
//				return
//			}
//			client := github.NewClient(conf.Client(context.Background(), tok))
//			user, _, err := client.Users.Get(context.Background(), "")
//			//client.Repositories.List(context.Background(), "", &github-auth.RepositoryListOptions{})
//			if err != nil {
//				ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to get user: %v", err))
//				return
//			}
//			persysToken, err := utils.GenerateToken(user)
//
//			data := models.UserInput{
//				Login:       stringFromPointer(user.Login),
//				Name:        stringFromPointer(user.Name),
//				Email:       stringFromPointer(user.Email),
//				Company:     stringFromPointer(user.Company),
//				URL:         stringFromPointer(user.URL),
//				GithubToken: tok.AccessToken,
//				UserID:      *user.ID,
//				PersysToken: persysToken,
//				State:       idempotencyID,
//				CreatedAt:   time.Now().String(),
//			}
//
//			ac.githubService.GetRepos(client, &data)
//
//			status, _ := ac.authService.SignInUser(&data)
//
//			ctx.JSON(http.StatusOK, status)
//		}
//	}
//}
//
//func (ac *AuthController) LoginHandler() gin.HandlerFunc {
//
//	return func(c *gin.Context) {
//		state = utils.RandToken()
//		c.JSON(http.StatusOK, gin.H{"URL": GetLoginURL(state)})
//	}
//	//ac.authService.SignInUser()
//
//}
//
//func (ac *AuthController) Setup(redirectURL string, scopes []string) {
//	// IMPORTANT SECURITY ISSUE
//	c := Credentials{
//		ClientID:     cnf.ClientID,
//		ClientSecret: cnf.ClientSecret,
//	}
//
//	conf = &oauth2.Config{
//		ClientID:     c.ClientID,
//		ClientSecret: c.ClientSecret,
//		RedirectURL:  redirectURL,
//		Scopes:       scopes,
//		Endpoint:     oauth2gh.Endpoint,
//	}
//}
//
//func GetLoginURL(state string) string {
//	return conf.AuthCodeURL(state)
//}
//
//func stringFromPointer(strPtr *string) (res string) {
//	if strPtr == nil {
//		res = ""
//		return res
//	}
//	res = *strPtr
//	return res
//}
