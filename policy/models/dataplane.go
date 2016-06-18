package models

type ModuleEntry struct {
	Id          string                 `json:"id"`
	ModuleType  string                 `json:"module_type"`
	DisplayName string                 `json:"display_name"`
	Perm        string                 `json:"permissions"`
	Config      map[string]interface{} `json:"config"`
	Tags        []string               `json:"tags"`
}

type TableEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
