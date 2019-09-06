package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/kotakanbe/go-cve-dictionary/config"
	"github.com/kotakanbe/go-cve-dictionary/db"
	log "github.com/kotakanbe/go-cve-dictionary/log"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

// Start starts CVE dictionary HTTP Server.
func Start(logDir string, driver db.DB) error {
	e := echo.New()
	e.Debug = config.Conf.Debug

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// setup access logger
	logPath := filepath.Join(logDir, "access.log")
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
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Output: f,
	}))

	// Routes
	e.GET("/health", health())
	e.GET("/cves/:id", getCve(driver))
	e.POST("/cpes", getCveByCpeName(driver))
	e.POST("/cpes/ids", getCveIDsByCpeName(driver))

	bindURL := fmt.Sprintf("%s:%s", config.Conf.Bind, config.Conf.Port)
	log.Infof("Listening on %s", bindURL)

	return e.Start(bindURL)
}

// Handler
func health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "")
	}
}

// Handler
func getCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		cveDetail, err := driver.Get(cveid)
		if err != nil {
			log.Errorf("%s", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

type cpeName struct {
	Name string `form:"name"`
}

func getCveByCpeName(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cpe := cpeName{}
		err := c.Bind(&cpe)
		if err != nil {
			log.Errorf("%s", err)
			return err
		}
		cveDetails, err := driver.GetByCpeURI(cpe.Name)
		if err != nil {
			log.Errorf("%s", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetails)
	}
}

func getCveIDsByCpeName(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cpe := cpeName{}
		err := c.Bind(&cpe)
		if err != nil {
			log.Errorf("%s", err)
			return err
		}
		cveIDs, err := driver.GetCveIDsByCpeURI(cpe.Name)
		if err != nil {
			log.Errorf("%s", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveIDs)
	}
}
