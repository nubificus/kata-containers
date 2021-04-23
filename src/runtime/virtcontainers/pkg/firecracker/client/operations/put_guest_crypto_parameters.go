// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/firecracker/client/models"
)

// NewPutGuestCryptoParams creates a new PutGuestCryptoParams object
// with the default values initialized.
func NewPutGuestCryptoParams() *PutGuestCryptoParams {
	var ()
	return &PutGuestCryptoParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPutGuestCryptoParamsWithTimeout creates a new PutGuestCryptoParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPutGuestCryptoParamsWithTimeout(timeout time.Duration) *PutGuestCryptoParams {
	var ()
	return &PutGuestCryptoParams{

		timeout: timeout,
	}
}

// NewPutGuestCryptoParamsWithContext creates a new PutGuestCryptoParams object
// with the default values initialized, and the ability to set a context for a request
func NewPutGuestCryptoParamsWithContext(ctx context.Context) *PutGuestCryptoParams {
	var ()
	return &PutGuestCryptoParams{

		Context: ctx,
	}
}

// NewPutGuestCryptoParamsWithHTTPClient creates a new PutGuestCryptoParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPutGuestCryptoParamsWithHTTPClient(client *http.Client) *PutGuestCryptoParams {
	var ()
	return &PutGuestCryptoParams{
		HTTPClient: client,
	}
}

/*PutGuestCryptoParams contains all the parameters to send to the API endpoint
for the put guest crypto operation typically these are written to a http.Request
*/
type PutGuestCryptoParams struct {

	/*Body
	  Guest crypto device properties

	*/
	Body *models.Crypto

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the put guest crypto params
func (o *PutGuestCryptoParams) WithTimeout(timeout time.Duration) *PutGuestCryptoParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the put guest crypto params
func (o *PutGuestCryptoParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the put guest crypto params
func (o *PutGuestCryptoParams) WithContext(ctx context.Context) *PutGuestCryptoParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the put guest crypto params
func (o *PutGuestCryptoParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the put guest crypto params
func (o *PutGuestCryptoParams) WithHTTPClient(client *http.Client) *PutGuestCryptoParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the put guest crypto params
func (o *PutGuestCryptoParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the put guest crypto params
func (o *PutGuestCryptoParams) WithBody(body *models.Crypto) *PutGuestCryptoParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the put guest crypto params
func (o *PutGuestCryptoParams) SetBody(body *models.Crypto) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PutGuestCryptoParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
