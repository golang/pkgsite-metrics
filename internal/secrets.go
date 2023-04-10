// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"context"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	smpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"golang.org/x/pkgsite-metrics/internal/derrors"
)

// GetSecret retrieves a secret from the GCP Secret Manager.
// secretFullName should be of the form "projects/PROJECT/secrets/NAME".
func GetSecret(ctx context.Context, secretFullName string) (_ string, err error) {
	defer derrors.Wrap(&err, "GetSecret(ctx, %q)", secretFullName)

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()
	result, err := client.AccessSecretVersion(ctx, &smpb.AccessSecretVersionRequest{
		Name: secretFullName + "/versions/latest",
	})
	if err != nil {
		return "", err
	}
	return string(result.Payload.Data), nil
}
