# Shared lint loader: assumptions

Built for REV-CHK-lintload (#4273). Each row is a reading a reviewer may want to change.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| REV-CHK-lintload-1 | `go list -deps -export -compiled` is the ground truth for what a build compiles into a package: the loader parses `CompiledGoFiles` (overlay text where `-overlay` replaces a file) and type-checks them against the export data go list built, so a lint judges what the build judges. | KRN-2 | A lint that must see what another toolchain builds needs its own build entry, not a second loader. |
| REV-CHK-lintload-2 | A file is unread when no load read it and a build of a load's GOOS and GOARCH could compile it with some other set of the tags its constraint names (cgo among them); a file only another platform compiles, a `//go:build ignore` file, and a file of a package a partial load left out are not. Assembly, syso and other non-Go sources, and cgo files (their C), are always unread. | KRN-2, HW-8 | A lint scoped to more platforms adds a load per platform; a lint wanting every ignored file refused (the HW-8 fence) reads `Package.Skipped`. |
| REV-CHK-lintload-3 | Only `_test.go` files import the loader, so childproc's gate exempts it although it runs go list (`TestOnlyTestsImportTheLoader`). | ARC-1 | A non-test importer fails that test; the exemption is removed with the package. |
