This package is deprecated.

Please use
1. the helpers in `test_util`
2. the struct definitions in `github.com/envoyproxy/go-control-plane`
3. their helper functions which handle `nil` function receivers allowing for
   easy method chaining

We will eventually refactor all tests to use the new approach and then delete
this package but in the meantime don't add to what is now considered tech debt
