// Package command holds test binary argv subcommand names shared by the
// helper binary and integration tests.
package command

const (
	PreagentParentReadChild = "preagent-parent-read-child" // preagent means it runs before the agent started
	ParentReadChild         = "parent-read-child"          // The parent and the child are reading the file
	Read                    = "read"
	ReadAndBlocked          = "read-and-blocked" // Read a file which should succeed and then read a blocked file should not be allowed
	WriteToReadonly         = "write-to-readonly"
	Connect                 = "connect"             // Connect to a TCP endpoint; failure means the connect did not succeed
	ReadMustBeDenied        = "read-must-be-denied" // Read a file that must be blocked; success is a failure

	// ParentReadAllowedChildReadDenied verifies negative inheritance: the parent
	// reads an allowed file, then spawns a child that must be denied a different,
	// guarded file. Proves a child cannot exceed the parent's grants.
	ParentReadAllowedChildReadDenied = "parent-read-allowed-child-read-denied"

	// FilelessExec copies the running binary into an anonymous in-memory file
	// (memfd) and tries to execute it. If the exec is blocked it exits 0; if the
	// in-memory image runs, the replaced image reports failure via FilelessRan.
	FilelessExec = "fileless-exec"

	// FilelessRan is the sentinel the in-memory image runs if it was NOT blocked.
	// Its only job is to signal that fileless execution succeeded (a failure for
	// the test).
	FilelessRan = "fileless-ran"
)
