package domain

import (
	"strings"
)

type RolePermissions struct {
	rolePermissions map[string][]string
}

func (p RolePermissions) IsAuthorizedFor(role string, routeName string) bool {
	perms := p.rolePermissions[role]
	for _, r := range perms {
		if r == strings.TrimSpace(routeName) {
			return true
		}
	}
	return false
}

func GetRolePermissions() RolePermissions {
	return RolePermissions{map[string][]string{
		"admin": {"SubscribeToEvent", "RunWorkflow", "GetWorkflowDetail", "DeleteWorkflow", "RetryRunWorkflow", "AddTestRuns", "AddWorkflow", "AllWorkflows", "DeleteRelease", "AllTestCases", "GetAProject", "GetAllProjects", "NewProject", "UpdateProject", "DeleteProject", "NewRelease", "GetAllRelease", "GetRelease", "UpdateRelease", "AddComponent", "AllComponent", "DeleteComponent", "UpdateComponent", "AddTestCase"},
		"user":  {"GetAProject", "RetryRunWorkflow", "DeleteWorkflow", "GetWorkflowDetail", "SubscribeToEvent", "RunWorkflow", "AddWorkflow", "AllWorkflows", "DeleteRelease", "AddTestRuns", "AllTestCases", "GetAllProjects", "NewProject", "UpdateProject", "DeleteProject", "NewRelease", "GetAllRelease", "GetRelease", "UpdateRelease", "AddComponent", "AllComponent", "DeleteComponent", "UpdateComponent", "AddTestCase"},
	}}
}
