// Package command holds bootstrap_helper argv subcommand names shared by the
// helper binary and integration tests.
package command

const (
	PreagentParentReadChild = "preagent-parent-read-child" // preagent means it runs before the agent started
	ParentReadChild         = "parent-read-child"          // The parent and the child are reading the file
	Read                    = "read"
	ReadAndBlocked          = "read-and-blocked" // Read a file which should succeed and then read a blocked file should not be allowed
	WriteToReadonly         = "write-to-readonly"
)
