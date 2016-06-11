package database

import (
	"fmt"

	"github.com/iovisor/iomodules/policy/log"
	"github.com/iovisor/iomodules/policy/models"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

//go:generate counterfeiter -o ../fakes/database.go --fake-name Database . Database
type Database interface {
	Endpoints() ([]models.EndpointEntry, error)
	Policies() ([]models.Policy, error)
	EndpointGroups() ([]models.EndpointGroup, error)
	AddEndpoint(models.EndpointEntry) error
	AddPolicy(models.Policy) error
	DeleteEndpoint(EpId string) error
	DeletePolicy(PolicyId string) error
	GetPolicy(PolicyId string) (models.Policy, error)
	GetEndpoint(EndpointId string) (models.EndpointEntry, error)
	GetEndpointByName(epg string) (models.EndpointEntry, error)
	AddEndpointGroup(models.EndpointGroup) error
	DeleteEndpointGroup(GroupId string) error
	GetEndpointGroup(GroupId string) (models.EndpointGroup, error)
}

type database struct {
	db *sqlx.DB
}

func Init(sqlUrl string) (Database, error) {

	sqlxDb, err := sqlx.Connect("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}

	schema := `CREATE TABLE Endpoints (
		id text PRIMARY KEY,
		ip text,
		epgid text SECONDARY KEY)`

	_, err = sqlxDb.Exec(schema)
	if err != nil {
		return nil, fmt.Errorf("create endpoint db : %s", err)
	}

	schema = `CREATE TABLE Policies (
	   id text PRIMARY KEY,
	   sourceepg text,
	   sourceport text,
	   destepg text,
	   destport text,
	   protocol text,
	   action text)`

	_, err = sqlxDb.Exec(schema)
	if err != nil {
		return nil, fmt.Errorf("create policies db : %s", err)
	}

	schema = `CREATE TABLE Epgs (
		id text PRIMARY KEY,
		epg text,
		wireid text)`

	_, err = sqlxDb.Exec(schema)
	if err != nil {
		return nil, fmt.Errorf("create endpoints db : %s", err)
	}
	return &database{
		db: sqlxDb,
	}, nil
}

func (dbPtr *database) AddEndpointGroup(epg models.EndpointGroup) error {
	_, err := dbPtr.db.NamedExec(`
	INSERT INTO Epgs (
		id, epg, wireid
	) VALUES (
		:id, :epg, :wireid
	)`, &epg)

	if err != nil {
		pqErr, ok := err.(*pq.Error)
		if !ok {
			return fmt.Errorf("insert: %s", err)
		}
		if pqErr.Code.Name() == "unique_violation" {
			return fmt.Errorf("add epg: record exists")
		}
		return fmt.Errorf("add epg to db: %s", pqErr.Code.Name())
	}
	return nil
}

func (dbPtr *database) DeleteEndpointGroup(id string) error {

	log.Info.Println("ID IS: ", id)
	result, err := dbPtr.db.Exec("DELETE FROM Epgs where id=$1", id)
	if err != nil {
		return fmt.Errorf("database delete endoint group: %s", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("database delete endpoint group : %s", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("database delete endpoint group : record not found")
	}
	return nil
}

func (dbPtr *database) EndpointGroups() ([]models.EndpointGroup, error) {
	epgs := []models.EndpointGroup{}
	err := dbPtr.db.Select(&epgs, "SELECT * FROM Epgs")
	if err != nil {
		return nil, fmt.Errorf("database get epgs: %s", err)
	}
	return epgs, nil
}

func (dbPtr *database) Endpoints() ([]models.EndpointEntry, error) {
	endpoints := []models.EndpointEntry{}
	err := dbPtr.db.Select(&endpoints, "SELECT * FROM endpoints")
	if err != nil {
		return nil, fmt.Errorf("database get endpoints: %s", err)
	}
	return endpoints, nil
}

func (dbPtr *database) AddEndpoint(endpoint models.EndpointEntry) error {
	_, err := dbPtr.db.NamedExec(`
	INSERT INTO Endpoints (
		id, ip, epgid
	) VALUES (
		:id, :ip, :epgid
	)`, &endpoint)

	if err != nil {
		pqErr, ok := err.(*pq.Error)
		if !ok {
			return fmt.Errorf("insert: %s", err)
		}
		if pqErr.Code.Name() == "unique_violation" {
			return fmt.Errorf("add endpoint: record exists")
		}
		return fmt.Errorf("add endpoint to db: %s", pqErr.Code.Name())
	}
	return nil
}
func (dbPtr *database) GetEndpointGroup(id string) (models.EndpointGroup, error) {
	epg := models.EndpointGroup{}
	err := dbPtr.db.Get(&epg, "SELECT * from Epgs WHERE id=$1", id)
	if err != nil {
		return epg, fmt.Errorf("database get endpoints: %s", err)
	}
	return epg, nil
}

func (dbPtr *database) GetEndpointByName(epg string) (models.EndpointEntry, error) {
	endpoints := models.EndpointEntry{}

	err := dbPtr.db.Get(&endpoints, "SELECT * from Endpoints WHERE epg=$1", epg)
	if err != nil {
		return endpoints, fmt.Errorf("database get endpoints by name: %s", err)
	}
	return endpoints, nil
}

func (dbPtr *database) GetEndpoint(id string) (models.EndpointEntry, error) {
	endpoints := models.EndpointEntry{}

	err := dbPtr.db.Get(&endpoints, "SELECT * from Endpoints WHERE id=$1", id)

	if err != nil {
		return endpoints, fmt.Errorf("database get endpoints: %s", err)
	}
	return endpoints, nil
}

func (dbPtr *database) DeleteEndpoint(id string) error {
	result, err := dbPtr.db.Exec("DELETE FROM Endpoints WHERE id=$1", id)
	if err != nil {
		return fmt.Errorf("database delete endpoint: %s", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("database delete endpoint : %s", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("database delete endpoint : record not found")
	}
	return nil
}

func (dbPtr *database) AddPolicy(policy models.Policy) error {
	_, err := dbPtr.db.NamedExec(`
	INSERT INTO Policies (
		id, sourceepg, sourceport, destepg, destport, protocol, action
	) VALUES (
		:id, :sourceepg, :sourceport, :destepg, :destport, :protocol, :action
	)`, &policy)

	if err != nil {
		pqErr, ok := err.(*pq.Error)
		if !ok {
			return fmt.Errorf("insert: %s", err)
		}
		if pqErr.Code.Name() == "unique_violation" {
			return fmt.Errorf("add policies: record exists")
		}
		return fmt.Errorf("add policies: %s", pqErr.Code.Name())
	}
	return nil
}

func (dbPtr *database) Policies() ([]models.Policy, error) {
	policies := []models.Policy{}
	err := dbPtr.db.Select(&policies, "SELECT * FROM policies")
	if err != nil {
		return nil, fmt.Errorf("database get policies: %s", err)
	}
	return policies, nil
}

func (dbPtr *database) DeletePolicy(id string) error {
	result, err := dbPtr.db.Exec("DELETE FROM Policies WHERE id=$1", id)
	if err != nil {
		fmt.Errorf("database delete endpoint: %s", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("database delete policies : %s", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("database delete policies : record not found")
	}
	return nil
}

func (dbPtr *database) GetPolicy(id string) (models.Policy, error) {
	policy := models.Policy{}
	err := dbPtr.db.Get(&policy, "SELECT * from Policies WHERE id=$1", id)
	if err != nil {
		return policy, fmt.Errorf("database get policy: %s", err)
	}
	return policy, nil
}
