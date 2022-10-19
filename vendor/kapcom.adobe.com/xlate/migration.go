package xlate

import (
	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"
)

// handle migration and return whether the ingress in involved in a migration
func (recv *CRDHandler) migrateIngress(ingress, ingressOld *Ingress) (migration bool) {
	if !config.EnableCRDMigration() {
		return
	}

	if ingress == nil && ingressOld != nil {
		// the ingress is being deleted

		highestPriorityIngress, nbIngresses := recv.findHighestPriorityIngress(ingressOld)
		// no matching ingress, no migration
		if highestPriorityIngress == nil {
			return
		}

		if ingressOld.Priority > highestPriorityIngress.Priority {
			// the next highest priority ingress becomes active
			recv.log.Info("migration activated via deletion",
				"name", ingressOld.Name, "ns", ingressOld.Namespace, "type", ingressOld.TypeURL,
				"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
			)
			new := highestPriorityIngress.DeepCopy()
			recv.migrated[new] = struct{}{}
			if nbIngresses == 1 {
				recv.unsetCRDMigrationHeader(new)
			} else {
				recv.setCRDMigrationHeader(new)
			}
			recv.OnUpdate(ingressOld, new)
			migration = true
		} else if ingressOld.Priority < highestPriorityIngress.Priority {
			recv.log.Info("migration - deleted ingress already inactive",
				"name", ingressOld.Name, "ns", ingressOld.Namespace, "type", ingressOld.TypeURL,
				"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
			)
			if nbIngresses == 1 {
				new := highestPriorityIngress.DeepCopy()
				recv.migrated[new] = struct{}{}
				recv.unsetCRDMigrationHeader(new)
				recv.OnUpdate(highestPriorityIngress, new)
				migration = true
			} else {
				// a non-programmed ingress is being deleted and there are other ingresses involved in migration
				// no XDS changes are needed
				migration = true
			}
		}
	} else if ingress != nil {
		// the ingress is being added or updated

		if _, exists := recv.migrated[ingress]; exists {
			// remove tracking since we're proceeding with a normal add/update
			delete(recv.migrated, ingress)
			return
		}

		highestPriorityIngress, nbIngresses := recv.findHighestPriorityIngress(ingress)
		// no matching ingress, no migration
		if highestPriorityIngress == nil {
			return
		}

		if ingress.Priority > highestPriorityIngress.Priority {
			recv.setCRDMigrationHeader(ingress)
			// if this is an update that was the highest already
			// then it's not migration but a regular update
			if ingressOld != nil && ingressOld.Priority > highestPriorityIngress.Priority {
				recv.log.Info("migration - updated ingress already active",
					"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
					"inactive", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				)
			} else { // both an add or an update from a lower priority is a migration
				recv.log.Info("migration activated",
					"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
					"inactive", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				)
				recv.migrated[ingress] = struct{}{}
				recv.OnUpdate(highestPriorityIngress, ingress)
				migration = true
			}
		} else if ingress.Priority < highestPriorityIngress.Priority {
			if ingressOld != nil && ingressOld.Priority < highestPriorityIngress.Priority {
				recv.log.Info("migration - updated ingress already inactive",
					"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
					"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				)
				// no update required and assume already migrated
				migration = true
			} else if ingressOld != nil {
				recv.log.Info("migration - updated ingress becomes inactive",
					"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
					"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				)
				new := highestPriorityIngress.DeepCopy()
				recv.migrated[new] = struct{}{}
				recv.setCRDMigrationHeader(new)
				recv.OnUpdate(ingressOld, new)
				migration = true
			} else {
				recv.log.Info("migration - added ingress is inactive",
					"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
					"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				)
				new := highestPriorityIngress.DeepCopy()
				recv.migrated[new] = struct{}{}
				recv.setCRDMigrationHeader(new)
				recv.OnUpdate(highestPriorityIngress, new)
				migration = true
			}
		}
	}

	return
}

// given an Ingress, returns the analogous Ingress with the highest priority and
// the total number of analogous ingresses
func (recv *CRDHandler) findHighestPriorityIngress(ingress *Ingress) (*Ingress, int) {
	var (
		highestPriorityIngress *Ingress
		nbIngresses            int
	)

	for iType, iMap := range recv.getNS(ingress.Namespace).ingressTypes {
		// small optimization: we have the type handy, so use it
		if iType == ingress.TypeURL {
			continue
		}
		if iPtr := iMap[ingress.Name]; iPtr != nil {
			if !ingress.Analogous(*iPtr) {
				continue
			}
			if highestPriorityIngress == nil {
				highestPriorityIngress = *iPtr
			} else {
				if (*iPtr).Priority > highestPriorityIngress.Priority {
					highestPriorityIngress = *iPtr
				}
			}
			nbIngresses++
		}
	}

	return highestPriorityIngress, nbIngresses
}

func (recv *CRDHandler) isHighestPriorityIngress(ingress *Ingress) (answer bool) {
	if highestPriorityIngress, _ := recv.findHighestPriorityIngress(ingress); highestPriorityIngress != nil {
		if highestPriorityIngress.Priority > ingress.Priority {
			return
		}
	}
	answer = true
	return
}

func (recv *CRDHandler) setCRDMigrationHeader(ingress *Ingress) {
	// obfuscate ingress.TypeURL
	var typeUrl string

	switch ingress.TypeURL {
	case "contour.heptio.com/v1/HTTPProxy":
		typeUrl = "hp"
	case "contour.heptio.com/v1beta1/IngressRoute":
		typeUrl = "ir"
	case "networking.k8s.io/v1/Ingress":
		typeUrl = "ig"
	default:
		typeUrl = ingress.TypeURL
	}

	ingress.VirtualHost.AddResponseHeader(constants.IngressHeader, typeUrl)
}

func (recv *CRDHandler) unsetCRDMigrationHeader(ingress *Ingress) {
	ingress.VirtualHost.RemoveResponseHeader(constants.IngressHeader)
}
