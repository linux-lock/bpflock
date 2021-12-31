// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DaemonConfigurationStatus Response to a daemon configuration request.
// Example: {"applied":{"options":{}},"daemonConfigurationMap":""}
//
// swagger:model DaemonConfigurationStatus
type DaemonConfigurationStatus struct {

	// applied
	Applied *DaemonConfigurationSpec `json:"applied,omitempty"`

	// Config map which contains all the active daemon configurations
	DaemonConfigurationMap interface{} `json:"daemonConfigurationMap,omitempty"`

	// immutable
	Immutable ConfigurationMap `json:"immutable,omitempty"`
}

// Validate validates this daemon configuration status
func (m *DaemonConfigurationStatus) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApplied(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateImmutable(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DaemonConfigurationStatus) validateApplied(formats strfmt.Registry) error {
	if swag.IsZero(m.Applied) { // not required
		return nil
	}

	if m.Applied != nil {
		if err := m.Applied.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("applied")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("applied")
			}
			return err
		}
	}

	return nil
}

func (m *DaemonConfigurationStatus) validateImmutable(formats strfmt.Registry) error {
	if swag.IsZero(m.Immutable) { // not required
		return nil
	}

	if m.Immutable != nil {
		if err := m.Immutable.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("immutable")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("immutable")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this daemon configuration status based on the context it is used
func (m *DaemonConfigurationStatus) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateApplied(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateImmutable(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DaemonConfigurationStatus) contextValidateApplied(ctx context.Context, formats strfmt.Registry) error {

	if m.Applied != nil {
		if err := m.Applied.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("applied")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("applied")
			}
			return err
		}
	}

	return nil
}

func (m *DaemonConfigurationStatus) contextValidateImmutable(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Immutable.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("immutable")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("immutable")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DaemonConfigurationStatus) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DaemonConfigurationStatus) UnmarshalBinary(b []byte) error {
	var res DaemonConfigurationStatus
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}