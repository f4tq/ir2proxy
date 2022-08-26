package xlate

import (
	"context"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants/annotations"

	"gopkg.in/inconshreveable/log15.v2"
)

type statusHandler struct {
	log            log15.Logger
	enabled        bool
	started        bool
	statusChan     chan *Ingress
	statusUpdaters map[string]statusUpdateFunc
}

type statusUpdateFunc func(string, *Ingress) error

func createStatusHandler(ctx context.Context, log log15.Logger) *statusHandler {
	handler := &statusHandler{
		log:     log,
		enabled: config.WriteCRDStatus(),
		// started zero-val
		statusChan:     make(chan *Ingress, 100),
		statusUpdaters: make(map[string]statusUpdateFunc),
	}
	return handler
}

func (recv *statusHandler) startStatusHandler(ctx context.Context) {
	recv.started = true
	go recv.loop(ctx)
}

func (recv *statusHandler) registerUpdaterFunc(name string, updFunc statusUpdateFunc) {
	recv.log.Info("register status update func", "type", name)
	recv.statusUpdaters[name] = updFunc
}

func (recv *statusHandler) updateStatus(ingress *Ingress) {
	if recv.enabled && recv.started {
		recv.statusChan <- ingress
	}
}

func (recv *statusHandler) loop(ctx context.Context) {
	log := recv.log
	log.Info("starting StatusHandler")

	for {
		select {
		case <-ctx.Done():
			log.Info("StatusHandler stopped")
			return
		case ingress := <-recv.statusChan:
			recv.updateIngressStatus(ingress)
		}
	}
}

func (recv *statusHandler) updateIngressStatus(ingress *Ingress) {
	if updateFunc, registered := recv.statusUpdaters[ingress.TypeURL]; registered {
		if updateFunc == nil {
			recv.log.Debug("nil status update func registered",
				"ns", ingress.Namespace, "name", ingress.Name, "type", ingress.TypeURL)
			return
		}

		recv.log.Debug("update Ingress status", "ns", ingress.Namespace, "name", ingress.Name,
			"type", ingress.TypeURL, annotations.IC, ingress.Class)

		err := updateFunc(ingress.Namespace, ingress)
		if err != nil {
			recv.log.Warn("error updating status", "ns", ingress.Namespace, "name", ingress.Name,
				"type", ingress.TypeURL, annotations.IC, ingress.Class, "err", err)
		}
		return
	}

	recv.log.Warn("no status update func registered",
		"ns", ingress.Namespace, "name", ingress.Name, "type", ingress.TypeURL)
}
