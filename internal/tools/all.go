package tools

// RegisterAll регистрирует все инструменты. Порядок — порядок в
// tools/list: сначала то, с чего модели стоит начинать.
func RegisterAll(r *Registry) {
	r.RegisterAccounts()
	r.RegisterRead()
	r.RegisterWrite()
	r.RegisterDrafts()
	r.RegisterSend()
	r.RegisterDiagnostics()
}
