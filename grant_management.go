package klon

type GrantManagementAction string

const (
	GrantManagementCreate  GrantManagementAction = "create"
	GrantManagementReplace GrantManagementAction = "replace"
	GrantManagementMerge   GrantManagementAction = "merge"
)
