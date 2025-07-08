package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	statelessauthhttp "medods_test/internal/adapters/auth/stateless/http"
	"medods_test/internal/adapters/auth/stateless/jwthelper"
	"medods_test/internal/adapters/auth/stateless/postgres"
	userhttp "medods_test/internal/adapters/user/http"
	"medods_test/internal/config"
	"medods_test/internal/core/auth/stateless"
	"medods_test/pkg/eventbus"
	"medods_test/pkg/guidgenerator"
	"medods_test/pkg/unikelongstring"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type App struct {
	_config *config.Config

	_context context.Context

	//инфраструктура
	_db                        *sql.DB
	_httpMux                   *http.ServeMux
	_authRepo                  stateless.AuthRepository
	_authHandler               *statelessauthhttp.Handler
	_accessTokenAlgoHelper     stateless.AccessTokenAlgoHelper
	_refreshTokenAlgoHelper    *unikelongstring.ULSHelper
	_tokenPairIDGenerator      stateless.StringIdGenerator
	_authHttpMiddlewareFactory *statelessauthhttp.MiddlewareFactory
	_logger                    *slog.Logger

	//логика
	_authService *stateless.StatelessAuthService

	//шины событий
	_userIpChangedBus *eventbus.OneCallbackBus[stateless.UserIPChangedEvent]

	//переменные, определяющие что стартовать
	startHttp bool

	//переменная, предотвращающая повторный запуск
	started bool
}

func (a *App) Run(ctx context.Context) {
	if a.started {
		return
	}
	a.started = true

	if ctx == nil {
		ctx = context.Background()
	}

	a._context = ctx

	a._userIpChangedBus.SetCallBack(func(event stateless.UserIPChangedEvent) {
		//запрос на эндпойнт
		if a.config().UserIPChangedWebhookUrl != "" {
			if err := a.doUserIPChangedWebhook(event); err != nil {
				a.Logger().Error("failed to call UserIPChangedWebhook", "error", err)
			} else {
				a.Logger().Info("UserIPChangedWebhook called successfully", "user_id", event.UserID, "new_ip", event.NewIP)
			}
		} else {
			a.Logger().Warn("UserIPChangedWebhookUrl is not configured, skipping webhook call")
		}

	})
	if a.startHttp {
		server := &http.Server{
			Addr:    ":" + fmt.Sprint(a.config().Port),
			Handler: a._httpMux,
			BaseContext: func(net.Listener) context.Context {
				return ctx
			},
		}

		go func() {
			<-ctx.Done()
			if err := server.Shutdown(context.Background()); err != nil {
				a.Logger().Error("failed to shutdown HTTP server", "error", err)
			}
		}()

		go func() {
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				panic(err)
			}
		}()
	}
}

func (a *App) AddHttp() error {
	service := a.authService()

	mux := a.httpServer()

	authHandler := statelessauthhttp.NewHandler(*service, *a.authMiddleware(), a.Logger())

	authHandler.RegisterRoutes(mux)

	userHandler := userhttp.NewHandler(*a.authMiddleware(), a.Logger())
	userHandler.RegisterRoutes(mux)

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

func (a *App) refreshTokenAlgoHelper() *unikelongstring.ULSHelper {
	if a._refreshTokenAlgoHelper == nil {
		a._refreshTokenAlgoHelper = unikelongstring.NewULSHelper()
	}
	return a._refreshTokenAlgoHelper
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
		a._authService = stateless.NewStatelessAuthService(a._authRepo, *a.accessTokenAlgoHelper(), a.refreshTokenAlgoHelper(), *a.tokenPairIDGenerator(), a.userIPChangedBus(), a.Logger())
	}
	return a._authService
}

func (a *App) authRepository() stateless.AuthRepository {
	if a._authRepo == nil {
		a._authRepo = postgres.NewPostgresAuthRepository(a.db(), a.refreshTokenAlgoHelper(), &postgres.Config{Prefix: a.config().Database.Prefix})
	}
	return a._authRepo
}

func (a *App) userIPChangedBus() *eventbus.OneCallbackBus[stateless.UserIPChangedEvent] {
	if a._userIpChangedBus == nil {
		a._userIpChangedBus = &eventbus.OneCallbackBus[stateless.UserIPChangedEvent]{}
	}
	return a._userIpChangedBus
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
		// fmt.Println(a.config().Database)
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

func (a *App) authMiddleware() *statelessauthhttp.MiddlewareFactory {
	if a._authHttpMiddlewareFactory == nil {
		a._authHttpMiddlewareFactory = statelessauthhttp.NewMiddlewareFactory(*a.accessTokenAlgoHelper())
	}
	return a._authHttpMiddlewareFactory
}

func (a *App) doUserIPChangedWebhook(event stateless.UserIPChangedEvent) error {
	if a.config().UserIPChangedWebhookUrl == "" {
		return fmt.Errorf("UserIPChangedWebhookUrl is not configured")
	}

	client := a.httpClient()

	body := fmt.Sprintf(`{"user_id": "%s", "new_ip": "%s"}`, event.UserID, event.NewIP)

	req, err := http.NewRequestWithContext(a._context, http.MethodPost, a.config().UserIPChangedWebhookUrl, strings.NewReader(body))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	return nil
}

func (a *App) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

func (a *App) Logger() *slog.Logger {
	if a._logger == nil {
		a._logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	return a._logger
}
