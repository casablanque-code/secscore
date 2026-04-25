package model

import (
"os"

"gopkg.in/yaml.v3"
)

var LoadedProfiles *Profiles

func LoadProfiles(path string) error {
data, err := os.ReadFile(path)
if err != nil {
return err
}

var p Profiles
if err := yaml.Unmarshal(data, &p); err != nil {
return err
}

LoadedProfiles = &p
return nil
}
