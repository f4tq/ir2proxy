package xlate

import (
	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"

	"github.com/google/uuid"
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

		if ingressOld.Priority >= highestPriorityIngress.Priority {
			// the next highest priority ingress becomes active
			recv.log.Info("migration activated via deletion",
				"name", ingressOld.Name, "ns", ingressOld.Namespace, "type", ingressOld.TypeURL,
				"fqdn", ingressOld.Fqdn,
				"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				"active_fqdn", highestPriorityIngress.Fqdn,
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
				"fqdn", ingressOld.Fqdn,
				"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				"active_fqdn", highestPriorityIngress.Fqdn,
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
	} else if ingress != nil && ingressOld == nil {
		// the ingress is being added

		if _, exists := recv.migrated[ingress]; exists {
			// remove tracking since we're proceeding with a normal add
			delete(recv.migrated, ingress)
			return
		}

		highestPriorityIngress, nbIngresses := recv.findHighestPriorityIngress(ingress)
		// no matching ingress, no migration
		if highestPriorityIngress == nil {
			return
		}

		if ingress.Priority >= highestPriorityIngress.Priority {
			recv.log.Info("migration activated via addition",
				"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
				"fqdn", ingress.Fqdn,
				"inactive", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				"inactive_fqdn", highestPriorityIngress.Fqdn,
			)
			recv.migrated[ingress] = struct{}{}
			recv.setCRDMigrationHeader(ingress)
			recv.OnUpdate(highestPriorityIngress, ingress)
			migration = true
		} else if ingress.Priority < highestPriorityIngress.Priority {
			recv.log.Info("migration - added ingress is inactive",
				"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
				"fqdn", ingress.Fqdn,
				"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
				"active_fqdn", highestPriorityIngress.Fqdn,
			)
			new := highestPriorityIngress.DeepCopy()
			recv.migrated[new] = struct{}{}
			recv.setCRDMigrationHeader(new)
			recv.OnUpdate(highestPriorityIngress, new)
			migration = true
		}
	} else if ingress != nil && ingressOld != nil {
		// the ingress is being updated

		if _, exists := recv.migrated[ingress]; exists {
			// remove tracking since we're proceeding with a normal add/update
			delete(recv.migrated, ingress)
			return
		}

		highestPriorityIngress, nbIngresses := recv.findHighestPriorityIngress(ingress)
		// no matching ingress, no migration, unless the old ingress was involved ("reverse" migration)
		if highestPriorityIngress == nil {
			OldHighestPriorityIngress, OldNbIngresses := recv.findHighestPriorityIngress(ingressOld)
			if OldHighestPriorityIngress == nil {
				return
			} else {
				if ingressOld.Priority > OldHighestPriorityIngress.Priority {
					// the old ingress was active, so re-activate the inactive one
					recv.log.Info("reverse migration - old inactive ingress becomes active, updated ingress treated as new",
						"name", OldHighestPriorityIngress.Name, "ns", OldHighestPriorityIngress.Namespace,
						"type", OldHighestPriorityIngress.TypeURL,
						"fqdn", OldHighestPriorityIngress.Fqdn,
						"inactive", ingressOld.TypeURL, "nb", OldNbIngresses,
						"inactive_fqdn", ingressOld.Fqdn,
						"new_name", ingress.Name, "new_ns", ingress.Namespace,
						"new_type", ingress.TypeURL,
						"new_fqdn", ingress.Fqdn,
					)

					newOld := OldHighestPriorityIngress.DeepCopy()
					recv.unsetCRDMigrationHeader(newOld)
					recv.migrated[newOld] = struct{}{}
					recv.OnUpdate(ingressOld, newOld)
					migration = true
					// because we're performing a migration, the update itself is aborted
					// so we need to force a new one
					new := ingress.DeepCopy()
					recv.migrated[new] = struct{}{}
					recv.OnAdd(new) // treat as an add
					return
				} else {
					// the old ingress was inactive, so consider it an add
					recv.log.Info("reverse migration - old ingress was inactive, updated ingress treated as new",
						"name", OldHighestPriorityIngress.Name, "ns", OldHighestPriorityIngress.Namespace,
						"type", OldHighestPriorityIngress.TypeURL,
						"fqdn", OldHighestPriorityIngress.Fqdn,
						"active", ingressOld.TypeURL, "nb", OldNbIngresses,
						"active_fqdn", ingressOld.Fqdn,
						"new_name", ingress.Name, "new_ns", ingress.Namespace,
						"new_type", ingress.TypeURL,
						"new_fqdn", ingress.Fqdn,
					)
					// remove the migration header
					newOld := OldHighestPriorityIngress.DeepCopy()
					recv.unsetCRDMigrationHeader(newOld)
					recv.migrated[newOld] = struct{}{}
					recv.OnUpdate(OldHighestPriorityIngress, newOld)
					// treat the updated ingress as an add
					new := ingress.DeepCopy()
					recv.migrated[new] = struct{}{}
					recv.OnAdd(new)
					migration = true
					return
				}
			}
			return
		}

		if ingress.Priority >= highestPriorityIngress.Priority {
			recv.setCRDMigrationHeader(ingress)
			// if the updated ingress is the highest priority already
			// then it's not migration but a regular update
			// unless it wasn't involved before
			if ingressOld.Priority > highestPriorityIngress.Priority {
				OldHighestPriorityIngress, _ := recv.findHighestPriorityIngress(ingressOld)
				if OldHighestPriorityIngress == nil {
					recv.log.Info("migration - uninvolved updated ingress activating itself",
						"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
						"fqdn", ingress.Fqdn,
						"inactive", highestPriorityIngress.TypeURL, "nb", nbIngresses,
						"inactive_fqdn", highestPriorityIngress.Fqdn,
						"removed_name", ingressOld.Name, "removed_ns", ingressOld.Namespace,
						"removed_type", ingressOld.TypeURL,
						"removed_fqdn", ingressOld.Fqdn,
					)

					recv.migrated[ingress] = struct{}{}
					recv.OnUpdate(highestPriorityIngress, ingress)
					migration = true
					// the OnUpdate() would have removed the old fqdn from the listener
					// but the routes remain, so force a removal here
					recv.removeVirtualHost(ingressOld) // test this with real cluster
				} else {
					recv.log.Info("migration - updated ingress already active",
						"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
						"fqdn", ingress.Fqdn,
						"inactive", highestPriorityIngress.TypeURL, "nb", nbIngresses,
						"inactive_fqdn", highestPriorityIngress.Fqdn,
					)
				}
			} else { // update from a lower priority is a migration
				recv.log.Info("migration activated via update",
					"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
					"fqdn", ingress.Fqdn,
					"inactive", highestPriorityIngress.TypeURL, "nb", nbIngresses,
					"inactive_fqdn", highestPriorityIngress.Fqdn,
				)
				recv.migrated[ingress] = struct{}{}
				recv.OnUpdate(highestPriorityIngress, ingress)
				migration = true
			}
		} else {
			// same as before: old can become inactive
			if ingressOld.Priority < highestPriorityIngress.Priority {
				OldHighestPriorityIngress, _ := recv.findHighestPriorityIngress(ingressOld)
				if OldHighestPriorityIngress == nil {
					recv.log.Info("migration - uninvolved updated ingress deactivating itself",
						"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
						"fqdn", ingress.Fqdn,
						"inactive", highestPriorityIngress.TypeURL, "nb", nbIngresses,
						"inactive_fqdn", highestPriorityIngress.Fqdn,
						"removed_name", ingressOld.Name, "removed_ns", ingressOld.Namespace,
						"removed_type", ingressOld.TypeURL,
						"removed_fqdn", ingressOld.Fqdn,
					)
					// set the header on the now active/involved ingress
					new := highestPriorityIngress.DeepCopy()
					recv.setCRDMigrationHeader(new)
					recv.migrated[new] = struct{}{}
					recv.OnUpdate(highestPriorityIngress, new)
					// the update ingress is now involved but inactive
					// normal update
					migration = false

				} else {
					recv.log.Info("migration - updated ingress already inactive",
						"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
						"fqdn", ingress.Fqdn,
						"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
						"active_fqdn", highestPriorityIngress.Fqdn,
					)
					// no update required and assume already migrated
					migration = true
				}
			} else {
				recv.log.Info("migration - updated ingress becomes inactive",
					"name", ingress.Name, "ns", ingress.Namespace, "type", ingress.TypeURL,
					"fqdn", ingress.Fqdn,
					"active", highestPriorityIngress.TypeURL, "nb", nbIngresses,
					"active_fqdn", highestPriorityIngress.Fqdn,
				)
				new := highestPriorityIngress.DeepCopy()
				recv.migrated[new] = struct{}{}
				recv.setCRDMigrationHeader(new)
				recv.OnUpdate(ingressOld, new)
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

	// reduced-scope loop if we have no migration-id
	if ingress.MigrationID == uuid.Nil {
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
	} else {
		recv.mapIngresses(func(ingress2 *Ingress) (stop bool) {
			if !ingress.Analogous(ingress2) {
				return
			}
			if highestPriorityIngress == nil {
				highestPriorityIngress = ingress2
			} else {
				if (ingress2).Priority > highestPriorityIngress.Priority {
					highestPriorityIngress = ingress2
				}
			}
			nbIngresses++
			return
		})
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
