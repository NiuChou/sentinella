package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func setupRoutes(r *gin.Engine) {
	r.GET("/api/users", listUsers)
	r.POST("/api/users", createUser)
	r.PUT("/api/users/:id", updateUser)
	r.DELETE("/api/users/:id", deleteUser)
}

func listUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"users": []string{}})
}

func createUser(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"created": true})
}

func updateUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"updated": true})
}

func deleteUser(c *gin.Context) {
	c.Status(http.StatusNoContent)
}
