// vim: set ts=8:sts=8:sw=8:noet

package hive

func NewAdapter(req *createModuleRequest) (Adapter, error) {
	uuid, err := NewUUID4()
	if err != nil {
		return nil, err
	}

	var adapter Adapter
	switch req.ModuleType {
	case "bpf":
		adapter = &BpfAdapter{
			id:     uuid,
			name:   req.DisplayName,
			config: make(map[string]interface{}),
		}
		if err := adapter.SetConfig(req.Config); err != nil {
			return nil, err
		}
	}
	return adapter, nil
}

type Adapter interface {
	ID() string
	Close() error
	Type() string
	Name() string
	Config() map[string]interface{}
	SetConfig(map[string]interface{}) error
	CreateInterface(name string) (string, error)
	DeleteInterface(id string) error
	Tables() []map[string]interface{}
	Table(name string) AdapterTable
}

type AdapterTablePair struct {
	Key   interface{} `json:"key"`
	Value interface{} `json:"value"`
}

type AdapterTable interface {
	ID() string
	Name() string
	Config() map[string]interface{}
	Get(key interface{}) (interface{}, bool)
	Set(key, val interface{}) error
	Delete(key interface{}) error
	Iter() <-chan AdapterTablePair
}
