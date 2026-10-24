package organization

import "github.com/ubgo/auth"

// Top-level fields: each request that carries extra fields also accepts them
// as top-level JSON keys, beside name and slug. UnmarshalJSON keeps the keys
// that are not the request's own (the core's auth.SplitBody, as the password
// sign-up does), and the operation joins them with the nested "fields" object
// through fieldSet.merge. A Go caller sets Fields; top is only ever filled by
// decoding.

// UnmarshalJSON keeps top-level field keys for create.
func (r *CreateRequest) UnmarshalJSON(data []byte) error {
	type plain CreateRequest
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = CreateRequest(p)
	r.top = top
	return nil
}

// UnmarshalJSON keeps top-level field keys inside update's data.
func (r *OrgUpdate) UnmarshalJSON(data []byte) error {
	type plain OrgUpdate
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = OrgUpdate(p)
	r.top = top
	return nil
}

// UnmarshalJSON keeps top-level field keys for invite.
func (r *InviteRequest) UnmarshalJSON(data []byte) error {
	type plain InviteRequest
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = InviteRequest(p)
	r.top = top
	return nil
}

// UnmarshalJSON keeps top-level field keys for create-team.
func (r *CreateTeamRequest) UnmarshalJSON(data []byte) error {
	type plain CreateTeamRequest
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = CreateTeamRequest(p)
	r.top = top
	return nil
}

// UnmarshalJSON keeps top-level field keys inside update-team's data.
func (r *TeamUpdate) UnmarshalJSON(data []byte) error {
	type plain TeamUpdate
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = TeamUpdate(p)
	r.top = top
	return nil
}

// UnmarshalJSON keeps top-level field keys for create-role.
func (r *CreateRoleRequest) UnmarshalJSON(data []byte) error {
	type plain CreateRoleRequest
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = CreateRoleRequest(p)
	r.top = top
	return nil
}

// UnmarshalJSON keeps top-level field keys inside update-role's data.
func (r *RoleUpdate) UnmarshalJSON(data []byte) error {
	type plain RoleUpdate
	var p plain
	top, err := auth.SplitBody(data, &p)
	if err != nil {
		return err
	}
	*r = RoleUpdate(p)
	r.top = top
	return nil
}
