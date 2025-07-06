package main

import (
	"database/sql"
	"fmt"
	statelessauthhttp "medods_test/internal/adapters/auth/stateless/http"
	"medods_test/internal/adapters/auth/stateless/jwthelper"
	"medods_test/internal/adapters/auth/stateless/postgres"
	"medods_test/internal/config"
	"medods_test/internal/core/auth/stateless"
	"medods_test/pkg/guidgenerator"
	"medods_test/pkg/unikelongstring"
	"net/http"
)

type App struct {
	_config *config.Config

	//инфраструктура
	_db                        *sql.DB
	_httpMux                   *http.ServeMux
	_authRepo                  stateless.AuthRepository
	_authHandler               *statelessauthhttp.Handler
	_accessTokenAlgoHelper     stateless.AccessTokenAlgoHelper
	_refreshTokenAlgoHelper    stateless.RefreshTokenAlgoHelper
	_tokenPairIDGenerator      stateless.StringIdGenerator
	_authHttpMiddlewareFactory *statelessauthhttp.MiddlewareFactory

	//логика
	_authService *stateless.StatelessAuthService

	//каналы событий
	userIPChanged chan stateless.UserIPChangedEvent

	//переменные, определяющие что стартовать
	startHttp bool

	//переменная, предотвращающая повторный запуск
	started bool
}

func (a *App) Run() {
	if a.startHttp {
		server := &http.Server{
			Addr:    ":" + fmt.Sprint(a.config().Port),
			Handler: a._httpMux,
		}

		err := server.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}
}

func (a *App) AddHttp() error {
	service := a.authService()

	mux := a.httpServer()

	authHandler := statelessauthhttp.NewHandler(*service, *a.AuthMiddleware())

	authHandler.RegisterRoutes(mux)

	a.startHttp = true

	return nil
}

func (a *App) httpServer() *http.ServeMux {
	if a._httpMux == nil {
		a._httpMux = http.NewServeMux()
	}
	return a._httpMux
}

func (a *App) accessTokenAlgoHelper() *stateless.AccessTokenAlgoHelper {
	if a._accessTokenAlgoHelper == nil {
		a._accessTokenAlgoHelper = jwthelper.NewJWTAccessTokenHelper(a.config().JWT.AccessSecret)
	}
	return &a._accessTokenAlgoHelper
}

func (a *App) refreshTokenAlgoHelper() *stateless.RefreshTokenAlgoHelper {
	if a._refreshTokenAlgoHelper == nil {
		a._refreshTokenAlgoHelper = unikelongstring.NewRefreshTokenHelper()
	}
	return &a._refreshTokenAlgoHelper
}

func (a *App) tokenPairIDGenerator() *stateless.StringIdGenerator {
	if a._tokenPairIDGenerator == nil {
		a._tokenPairIDGenerator = guidgenerator.GuidGenerator{}
	}
	return &a._tokenPairIDGenerator
}

func (a *App) authService() *stateless.StatelessAuthService {
	if a._authService == nil {
		a._authRepo = a.authRepository()
		a._authService = stateless.NewStatelessAuthService(a._authRepo, *a.accessTokenAlgoHelper(), *a.refreshTokenAlgoHelper(), *a.tokenPairIDGenerator(), nil, nil)
	}
	return a._authService
}

func (a *App) authRepository() stateless.AuthRepository {
	if a._authRepo == nil {
		a._authRepo = postgres.NewPostgresAuthRepository(a.db(), &postgres.Config{Prefix: a.config().Database.Prefix})
	}
	return a._authRepo
}

func (a *App) config() *config.Config {
	if a._config == nil {
		a._config = &config.Config{}
		a._config.Load()
	}
	return a._config
}

func (a *App) db() *sql.DB {
	if a._db == nil {
		cfg := a.config().Database
		var dsn string
		var driver string
		switch cfg.DBType {
		case "postgres":
			driver = "postgres"
			dsn = fmt.Sprintf(
				"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
				cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name,
			)
		// Можно добавить другие драйверы (mysql, sqlite и т.д.)
		default:
			panic("unsupported database type: " + cfg.DBType)
		}
		db, err := sql.Open(driver, dsn)
		if err != nil {
			panic(err)
		}
		if err := db.Ping(); err != nil {
			panic(err)
		}
		a._db = db
	}
	return a._db
}

func (a *App) AuthMiddleware() *statelessauthhttp.MiddlewareFactory {
	if a._authHttpMiddlewareFactory == nil {
		a._authHttpMiddlewareFactory = statelessauthhttp.NewMiddlewareFactory(*a.accessTokenAlgoHelper())
	}
	return a._authHttpMiddlewareFactory
}

