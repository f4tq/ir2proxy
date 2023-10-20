package xds

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"kapcom.adobe.com/logger"
)

var log = logger.New()

type Response struct {
	TypeURL      string `json:"typeURL"`
	ResourceName string `json:"resourceName"`
	Message      string `json:"message"`
}

func init() {
	http.HandleFunc("/xds/metrics/nack/increment", incrementMetricXdsNacksHandler)
	http.HandleFunc("/xds/metrics/nack/delete", deleteMetricXdsNacksHandler)
}

func sendJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

func incrementMetricXdsNacksHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the query parameters to get the label values
	typeURL := r.URL.Query().Get("typeURL")

	// Check if the required parameters are present
	if typeURL == "" {
		http.Error(w, "Missing typeURL as query parameter", http.StatusBadRequest)
		return
	}

	id, err := uuid.NewRandom()
	if err != nil {
		log.Error("Failed to generate UUID:", err)
		return
	}
	resourceName := id.String()

	// Increment the metric with the given label values
	xdsNacks.WithLabelValues(typeURL, resourceName).Inc()

	message := fmt.Sprintf("XdsNacks Metric incremented for typeURL=%s, resourceName=%s", typeURL, resourceName)

	log.Info(message)

	response := Response{
		TypeURL:      typeURL,
		ResourceName: resourceName,
		Message:      message,
	}

	sendJSONResponse(w, response)
}

func deleteMetricXdsNacksHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the query parameters to get the label values
	typeURL := r.URL.Query().Get("typeURL")
	resourceName := r.URL.Query().Get("resourceName")

	// Check if the required parameters are present
	if typeURL == "" {
		http.Error(w, "Missing typeURL as query parameters", http.StatusBadRequest)
		return
	}
	if resourceName == "" {
		http.Error(w, "Missing resourceName as query parameters", http.StatusBadRequest)
		return
	}

	// Delete the metric with the given label values
	if !xdsNacks.DeleteLabelValues(typeURL, resourceName) {
		http.Error(w, "Failed to delete label values", http.StatusInternalServerError)
		return
	}

	message := fmt.Sprintf("XdsNacks Metric deleted for typeURL=%s, resourceName=%s", typeURL, resourceName)

	log.Info(message)

	response := Response{
		TypeURL:      typeURL,
		ResourceName: resourceName,
		Message:      message,
	}

	sendJSONResponse(w, response)
}
