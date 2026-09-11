// Package command holds test binary argv subcommand names shared by the test binary and integration tests.
package command

const (
	PreagentParentReadChild          = "preagent-parent-read-child"
	ParentReadChild                  = "parent-read-child"
	Read                             = "read"
	ReadAndBlocked                   = "read-and-blocked"
	WriteToReadonly                  = "write-to-readonly"
	Connect                          = "connect"
	ReadMustBeDenied                 = "read-must-be-denied"
	ParentReadAllowedChildReadDenied = "parent-read-allowed-child-read-denied"
	FilelessExec                     = "fileless-exec"
	FilelessRan                      = "fileless-ran"
	UpdateFD                         = "update-fd"
	GetFDID                          = "get-fd-id"
	List                             = "list"
	Update                           = "update"
	ExitBlocked                      = 0
	ExitAccessible                   = 10
	ExitError                        = 2
)
