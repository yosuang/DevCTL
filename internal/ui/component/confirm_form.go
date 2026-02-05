package component

import (
	"github.com/charmbracelet/huh"
)

type ConfirmFormConfig struct {
	Title        string
	Desc         string
	DefaultValue bool
}

func NewConfirmForm(cfg ConfirmFormConfig) (bool, error) {
	confirmed := cfg.DefaultValue

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(cfg.Title).
				Description(cfg.Desc).
				Value(&confirmed),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	return confirmed, nil
}
