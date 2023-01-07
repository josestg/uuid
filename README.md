# UUID

UUID is a 128 bit (16 byte) Universal Unique Identifier as defined in RFC 4122.

## Example

```go
package main

import "github.com/josestg/uuid"

func main() {
	v4 := uuid.NewV4Generator(uuid.SecureReader)

	uid, err := v4.NewUUID()
	if err != nil {
		panic(err)
	}

	println(uid.String())
}

```