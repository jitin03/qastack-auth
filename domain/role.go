package domain

import (
	"github.com/jmoiron/sqlx/types"
)

type RolePermission struct {
	Routes types.JSONText `db:"routes"`
}
type RolePermissions interface {
	// rolePermissions map[string][]string

}



// func (p RolePermissions) IsAuthorizedFor(role string, routeName string) bool {
// 	perms := p.rolePermissions[role]
// 	for _, r := range perms {
// 		if r == strings.TrimSpace(routeName) {
// 			return true
// 		}
// 	}
// 	return false
// }

// func GetRolePermissions() RolePermissions {
// 	return RolePermissions{map[string][]string{
// 		"admin": {"GetProjectTestsProgress", "GetComponentTestCases", "GetProjectTestsStatus", "GetComponent", "UploadTestCases", "DownloadTestResult", "GetTestResultsUploads", "GetTestCaseRunHistory", "UploadResult", "UpdateWorkflowConfig", "WorkflowLogs", "UpdateWorkflowStatus", "ReSubmitRunWorkflow", "UpdateTestStatus", "GetProjectTestRun", "GetTestCaseTitlesForTestRun", "UpdateTestRun", "SubscribeToEvent", "RunWorkflow", "UpdateTestCase", "GetTestCase", "GetTotalTestCases", "AllProjectTestRuns", "GetWorkflowDetail", "DeleteWorkflow", "RetryRunWorkflow", "AddTestRuns", "AddWorkflow", "AllWorkflows", "DeleteRelease", "AllTestCases", "GetAProject", "GetAllProjects", "NewProject", "UpdateProject", "DeleteProject", "NewRelease", "GetAllRelease", "GetRelease", "UpdateRelease", "AddComponent", "AllComponent", "DeleteComponent", "UpdateComponent", "AddTestCase"},
// 		"user":  {"GetProjectTestsProgress", "GetComponentTestCases", "GetProjectTestsStatus", "GetComponent", "UploadTestCases", "DownloadTestResult", "GetTestResultsUploads", "GetTestCaseRunHistory", "UploadResult", "UpdateWorkflowConfig", "WorkflowLogs", "UpdateWorkflowStatus", "ReSubmitRunWorkflow", "GetAProject", "UpdateTestStatus", "GetTestCaseTitlesForTestRun", "GetProjectTestRun", "UpdateTestRun", "RetryRunWorkflow", "GetTestCase", "UpdateTestCase", "GetTotalTestCases", "AllProjectTestRuns", "DeleteWorkflow", "GetWorkflowDetail", "SubscribeToEvent", "RunWorkflow", "AddWorkflow", "AllWorkflows", "DeleteRelease", "AddTestRuns", "AllTestCases", "GetAllProjects", "NewProject", "UpdateProject", "DeleteProject", "NewRelease", "GetAllRelease", "GetRelease", "UpdateRelease", "AddComponent", "AllComponent", "DeleteComponent", "UpdateComponent", "AddTestCase"},
// 	}}
// }
