package server

import (
	"fmt"
	"net/http"
	"os"

	"github.com/kotakanbe/go-cve-dictionary/config"
	db "github.com/kotakanbe/go-cve-dictionary/db"
	log "github.com/kotakanbe/go-cve-dictionary/log"
	"github.com/labstack/echo"
	"github.com/labstack/echo/engine/standard"
	"github.com/labstack/echo/middleware"
)

// Start starts CVE dictionary HTTP Server.
func Start() error {
	e := echo.New()
	e.SetDebug(config.Conf.Debug)

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// setup access logger
	logPath := "/var/log/vuls/access.log"
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		if _, err := os.Create(logPath); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	logconf := middleware.DefaultLoggerConfig
	logconf.Output = f
	e.Use(middleware.LoggerWithConfig(logconf))

	// Routes
	e.Get("/health", health())
	e.Get("/cves/:id", getCve())
	e.Post("/cpes", getCveByCpeName())

	bindURL := fmt.Sprintf("%s:%s", config.Conf.Bind, config.Conf.Port)
	log.Infof("Listening on %s", bindURL)

	e.Run(standard.New(bindURL))
	return nil
}

// Handler
func health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "")
	}
}

// Handler
func getCve() echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		cveDetail := db.Get(cveid)
		return c.JSON(http.StatusOK, cveDetail)
	}
}

type cpeName struct {
	Name string `form:"name"`
}

func getCveByCpeName() echo.HandlerFunc {
	return func(c echo.Context) error {
		cpe := cpeName{}
		err := c.Bind(&cpe)
		if err != nil {
			return err
		}
		cveDetails := db.GetByCpeName(cpe.Name)
		return c.JSON(http.StatusOK, cveDetails)
	}
}
