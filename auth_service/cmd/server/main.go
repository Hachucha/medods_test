package main

import (
	"context"
	"os/signal"
	"syscall"
)
// @title Auth API
// @version 1.0
// @description JWT(stateless toket) авторизация
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
func main() {
	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	
	app := App{}
	app.AddHttp();
	
	app.Run(rootCtx)

	<-rootCtx.Done()
	
}