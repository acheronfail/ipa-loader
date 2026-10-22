package apple

import "context"

// TeamsWithAllowance supplements membership hints with the quota Apple
// reports for listAppIds. A missing allowance never prevents signing in and
// never becomes an invented unlimited plan or a guessed remaining count.
func (c *Client) TeamsWithAllowance(ctx context.Context, session *Session) ([]Team, error) {
	teams, err := c.Teams(ctx, session)
	if err != nil {
		return nil, err
	}
	for i := range teams {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		response, err := c.Request(ctx, session, "listAppIds", nil, teams[i].ID)
		if err == nil {
			applyAppIDAllowance(&teams[i], response)
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return teams, nil
}

func applyAppIDAllowance(team *Team, response map[string]any) {
	maximum, maxOK := number(response["maxQuantity"])
	available, availableOK := number(response["availableQuantity"])
	if !maxOK || !availableOK || maximum <= 0 || available < 0 || available > maximum {
		return
	}
	team.LimitKnown = true
	team.AppIDsUnlimited = false
	team.AppIDLimit = maximum
	team.AppIDsAvailable = available
	team.AvailabilityKnown = true
}
