package console

// The engines register themselves with the engine registry.
import (
	_ "github.com/DavidGodefroid/locksql/internal/engine/mysql"
	_ "github.com/DavidGodefroid/locksql/internal/engine/postgres"
	_ "github.com/DavidGodefroid/locksql/internal/engine/sqlite"
)
