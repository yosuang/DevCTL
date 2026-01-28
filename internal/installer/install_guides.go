package installer

import "devctl/pkg/pkgmgr"

// InstallGuide provides manual installation instructions for a package manager.
type InstallGuide struct {
	ManagerType  pkgmgr.ManagerType
	Platform     string
	Instructions []string
	URL          string
	VerifyCmd    string
}

// GetInstallGuide returns the installation guide for a package manager on a specific platform.
func GetInstallGuide(managerType pkgmgr.ManagerType, platform string) *InstallGuide {
	switch managerType {
	case pkgmgr.ManagerTypeScoop:
		return getScoopGuide()
	case pkgmgr.ManagerTypePwsh:
		return getPwshGuide()
	case pkgmgr.ManagerTypeBrew:
		return getBrewGuide(platform)
	default:
		return nil
	}
}

func getScoopGuide() *InstallGuide {
	return &InstallGuide{
		ManagerType: pkgmgr.ManagerTypeScoop,
		Platform:    "windows",
		Instructions: []string{
			"Open PowerShell",
			"Run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser",
			"Run: Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression",
			"Restart your terminal after installation",
		},
		URL:       "https://scoop.sh",
		VerifyCmd: "scoop --version",
	}
}

func getPwshGuide() *InstallGuide {
	return &InstallGuide{
		ManagerType: pkgmgr.ManagerTypePwsh,
		Platform:    "windows",
		Instructions: []string{
			"Visit the PowerShell GitHub releases page",
			"Download the latest .msi installer for Windows",
			"Run the installer and follow the prompts",
			"Restart your terminal after installation",
		},
		URL:       "https://github.com/PowerShell/PowerShell/releases",
		VerifyCmd: "pwsh --version",
	}
}

func getBrewGuide(platform string) *InstallGuide {
	guide := &InstallGuide{
		ManagerType: pkgmgr.ManagerTypeBrew,
		Platform:    platform,
		URL:         "https://brew.sh",
		VerifyCmd:   "brew --version",
	}

	if platform == "darwin" {
		guide.Instructions = []string{
			"Open Terminal",
			"Run: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"",
			"Follow the on-screen instructions",
			"Add Homebrew to your PATH as instructed",
		}
	} else {
		guide.Instructions = []string{
			"Open Terminal",
			"Run: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"",
			"Follow the on-screen instructions",
			"Add Homebrew to your PATH: eval \"$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)\"",
		}
	}

	return guide
}
