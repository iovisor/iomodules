package models

type Pool struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	Scheduler string `json:"scheduler"`
}

type Server struct {
	Id     string `json:"id"`
	Ip     string `json:"ip"`
	Port   string `json:"port"`
	PoolId string `json:"poolid"`
}

type Service struct {
	Id     string `json:"id"`
	Ip     string `json:"ip"`
	Port   string `json:"port"`
	PoolId string `json:"poolid"`
}
