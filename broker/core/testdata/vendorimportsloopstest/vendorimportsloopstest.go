// Package vendorimportsloopstest reaches loopstest through a vendored
// package, as a planted file under broker/vendor would; the check must
// follow imports outside the module too.
package vendorimportsloopstest

import _ "example.com/hop"
