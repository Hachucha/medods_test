package main

// @title Auth API
// @version 1.0
// @description JWT(stateless toket) авторизация
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
func main() {
	app := App{}

	app.AddHttp();

	app.Run()
}