package domain

import (
	"github.com/jmoiron/sqlx"
)

type RolePermissionRepositoryDb struct {
	client *sqlx.DB
}

func NewRolePermissionDb(dbClient *sqlx.DB) RolePermissionRepositoryDb {
	return RolePermissionRepositoryDb{dbClient}
}
