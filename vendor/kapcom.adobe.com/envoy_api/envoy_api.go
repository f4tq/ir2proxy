package envoy_api

import (
	"encoding/json"
	"net/http"
	"sort"

	"kapcom.adobe.com/config"

	"github.com/onsi/ginkgo"
	"gopkg.in/inconshreveable/log15.v2"
)

type (
	ConfigDump struct {
		Configs []SomeConfig `json:"configs"`
	}

	SomeConfig struct {
		Type                  string           `json:"@type"`
		StaticClusters        *json.RawMessage `json:"static_clusters,omitempty"`
		DynamicActiveClusters *json.RawMessage `json:"dynamic_active_clusters,omitempty"`
		StaticListeners       *json.RawMessage `json:"static_listeners,omitempty"`
		DynamicListeners      *json.RawMessage `json:"dynamic_listeners,omitempty"`
		StaticRouteConfigs    *json.RawMessage `json:"static_route_configs,omitempty"`
		DynamicRouteConfigs   *json.RawMessage `json:"dynamic_route_configs,omitempty"`
		DynamicActiveSecrets  *json.RawMessage `json:"dynamic_active_secrets,omitempty"`
	}

	ApiCluster struct {
		VersionInfo string  `json:"version_info"`
		Cluster     Cluster `json:"cluster"`
	}

	ListenerState struct {
		VersionInfo string   `json:"version_info"`
		Listener    Listener `json:"listener"`
	}

	ApiListener struct {
		Name         string        `json:"name"`
		ActiveState  ListenerState `json:"active_state"`
		WarmingState ListenerState `json:"warming_state"`
		ErrorState   struct {
			FailedConfiguration struct{} `json:"failed_configuration"`
			Details             string   `json:"details"`
		} `json:"error_state,omitempty"`
	}

	ApiRoute struct {
		VersionInfo string      `json:"version_info"`
		RouteConfig RouteConfig `json:"route_config"`
	}

	ApiSecret struct {
		Name        string `json:"name"`
		VersionInfo string `json:"version_info"`
		Secret      Secret `json:"secret"`
	}

	ServerInfo struct {
		Version            string `json:"version"`
		State              string `json:"state"`
		CommandLineOptions struct {
			BaseID                   string `json:"base_id"`
			Concurrency              int    `json:"concurrency"`
			ConfigPath               string `json:"config_path"`
			ConfigYaml               string `json:"config_yaml"`
			AllowUnknownStaticFields bool   `json:"allow_unknown_static_fields"`
			AdminAddressPath         string `json:"admin_address_path"`
			LocalAddressIPVersion    string `json:"local_address_ip_version"`
			LogLevel                 string `json:"log_level"`
			ComponentLogLevel        string `json:"component_log_level"`
			LogFormat                string `json:"log_format"`
			LogPath                  string `json:"log_path"`
			HotRestartVersion        bool   `json:"hot_restart_version"`
			ServiceCluster           string `json:"service_cluster"`
			ServiceNode              string `json:"service_node"`
			ServiceZone              string `json:"service_zone"`
			Mode                     string `json:"mode"`
			DisableHotRestart        bool   `json:"disable_hot_restart"`
			EnableMutexTracing       bool   `json:"enable_mutex_tracing"`
			RestartEpoch             int    `json:"restart_epoch"`
			FileFlushInterval        string `json:"file_flush_interval"`
			DrainTime                string `json:"drain_time"`
			ParentShutdownTime       string `json:"parent_shutdown_time"`
			CpusetThreads            bool   `json:"cpuset_threads"`
		} `json:"command_line_options"`
		UptimeCurrentEpoch string `json:"uptime_current_epoch"`
		UptimeAllEpochs    string `json:"uptime_all_epochs"`
	}

	HostStatus struct {
		Address struct {
			SocketAddress struct {
				Address   string `json:"address"`
				PortValue int    `json:"port_value"`
			} `json:"socket_address"`
		} `json:"address"`
		Stats []struct {
			Name string `json:"name"`
			Type string `json:"type,omitempty"`
		} `json:"stats"`
		HealthStatus struct {
			EdsHealthStatus string `json:"eds_health_status"`
		} `json:"health_status"`
		Weight int `json:"weight"`
	}
)

type ApiRouteByName []ApiRoute

func (recv ApiRouteByName) Len() int {
	return len(recv)
}
func (recv ApiRouteByName) Less(i, j int) bool {
	return recv[i].RouteConfig.Name < recv[j].RouteConfig.Name
}
func (recv ApiRouteByName) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

type ApiListenerByName []ApiListener

func (recv ApiListenerByName) Len() int {
	return len(recv)
}
func (recv ApiListenerByName) Less(i, j int) bool {
	return recv[i].Name < recv[j].Name
}
func (recv ApiListenerByName) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

type ApiSecretByName []ApiSecret

func (recv ApiSecretByName) Len() int {
	return len(recv)
}
func (recv ApiSecretByName) Less(i, j int) bool {
	return recv[i].Name < recv[j].Name
}
func (recv ApiSecretByName) Swap(i, j int) {
	recv[i], recv[j] = recv[j], recv[i]
}

func GetConfigDump(log log15.Logger, endpoint string) (dump *ConfigDump, success bool) {
	res, err := http.Get(endpoint + "/config_dump?include_eds")
	if err != nil {
		log.Error("http.Get", "Error", err)
		return
	}

	dump = new(ConfigDump)
	err = json.NewDecoder(res.Body).Decode(dump)
	if err != nil {
		log.Error("json.Unmarshal", "Error", err)
		return
	}

	success = res.StatusCode == 200
	return
}

func GetServerInfo(log log15.Logger, endpoint string) (serverInfo *ServerInfo, success bool) {
	req, err := http.NewRequest("GET", endpoint+"/server_info", nil)
	if err != nil {
		log.Error("http.NewRequest", "Error", err)
		return
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		if !config.Testing() {
			log.Error("http.Get", "Error", err)
		}
		return
	}
	defer res.Body.Close()

	serverInfo = new(ServerInfo)
	err = json.NewDecoder(res.Body).Decode(serverInfo)
	if err != nil {
		if !config.Testing() {
			log.Error("json.Decode", "Error", err)
		}
		return
	}

	success = res.StatusCode == 200
	return
}

func Quit(log log15.Logger, endpoint string) (success bool) {
	req, err := http.NewRequest("POST", endpoint+"/quitquitquit", nil)
	if err != nil {
		log.Error("http.NewRequest", "Error", err)
		return
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("http.Post", "Error", err)
		return
	}
	res.Body.Close()

	success = res.StatusCode == 200
	return
}

func UnmarshalApiClusters(log log15.Logger, dump *ConfigDump) (clusters []ApiCluster, success bool) {
	clustersType := "type.googleapis.com/envoy.admin.v3.ClustersConfigDump"

	for _, something := range dump.Configs {
		if something.Type != clustersType {
			continue
		}
		if something.DynamicActiveClusters == nil {
			log.Error("dynamic_active_clusters == nil")
			return
		}

		err := json.Unmarshal(*something.DynamicActiveClusters, &clusters)
		if err != nil {
			log.Error("json.Unmarshal", "Error", err)
			ginkgo.GinkgoWriter.Write(*something.DynamicActiveClusters)
			return
		}
		success = true
		return
	}
	log.Error("UnmarshalApiClusters found no " + clustersType)
	return
}

func GetDynamicClusters(log log15.Logger, endpoint string) ([]ApiCluster, bool) {

	dump, configDumpSuccess := GetConfigDump(log, endpoint)
	if !configDumpSuccess {
		return nil, false
	}

	return UnmarshalApiClusters(log, dump)
}

func UnmarshalApiListeners(log log15.Logger, dump *ConfigDump) (listeners []ApiListener, success bool) {
	listenersType := "type.googleapis.com/envoy.admin.v3.ListenersConfigDump"

	for _, something := range dump.Configs {
		if something.Type != listenersType {
			continue
		}
		if something.DynamicListeners == nil {
			log.Error("dynamic_listeners == nil")
			return
		}

		err := json.Unmarshal(*something.DynamicListeners, &listeners)
		if err != nil {
			log.Error("json.Unmarshal", "Error", err)
			ginkgo.GinkgoWriter.Write(*something.DynamicListeners)
			return
		}

		sort.Stable(ApiListenerByName(listeners))

		success = true
		return
	}
	log.Error("UnmarshalApiListeners found no " + listenersType)
	return
}

func GetDynamicListeners(log log15.Logger, endpoint string) ([]ApiListener, bool) {

	dump, configDumpSuccess := GetConfigDump(log, endpoint)
	if !configDumpSuccess {
		return nil, false
	}

	return UnmarshalApiListeners(log, dump)
}

func UnmarshalApiRoutes(log log15.Logger, dump *ConfigDump) (routes []ApiRoute, success bool) {
	routesType := "type.googleapis.com/envoy.admin.v3.RoutesConfigDump"

	for _, something := range dump.Configs {
		if something.Type != routesType {
			continue
		}
		if something.DynamicRouteConfigs == nil {
			log.Error("dynamic_route_configs == nil")
			return
		}

		err := json.Unmarshal(*something.DynamicRouteConfigs, &routes)
		if err != nil {
			log.Error("json.Unmarshal", "Error", err)
			ginkgo.GinkgoWriter.Write(*something.DynamicRouteConfigs)
			return
		}

		sort.Stable(ApiRouteByName(routes))

		success = true
		return
	}
	log.Error("UnmarshalApiRoutes found no " + routesType)
	return
}

func GetDynamicRoutes(log log15.Logger, endpoint string) ([]ApiRoute, bool) {

	dump, configDumpSuccess := GetConfigDump(log, endpoint)
	if !configDumpSuccess {
		return nil, false
	}

	return UnmarshalApiRoutes(log, dump)
}

func UnmarshalApiSecrets(log log15.Logger, dump *ConfigDump) (secrets []ApiSecret, success bool) {
	secretsType := "type.googleapis.com/envoy.admin.v3.SecretsConfigDump"

	for _, something := range dump.Configs {
		if something.Type != secretsType {
			continue
		}
		if something.DynamicActiveSecrets == nil {
			log.Error("dynamic_active_secrets == nil")
			return
		}

		err := json.Unmarshal(*something.DynamicActiveSecrets, &secrets)
		if err != nil {
			log.Error("json.Unmarshal", "Error", err)
			ginkgo.GinkgoWriter.Write(*something.DynamicActiveSecrets)
			return
		}

		sort.Stable(ApiSecretByName(secrets))

		success = true
		return
	}
	log.Error("UnmarshalApiSecrets found no " + secretsType)
	return
}

func GetDynamicSecrets(log log15.Logger, endpoint string) ([]ApiSecret, bool) {
	dump, configDumpSuccess := GetConfigDump(log, endpoint)
	if !configDumpSuccess {
		return nil, false
	}
	return UnmarshalApiSecrets(log, dump)
}
