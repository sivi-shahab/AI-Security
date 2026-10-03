# METADATA
# description: |
#   The destination the PDP decides on. For an app in the catalog (data.aisec.catalog, ticket 16), the catalog is
#   the source of truth for sanction, hosting region and training use; a status change reaches every decision with
#   the next release. Apps not in the catalog keep what the PEP sent (PEPs send unsanctioned for those).
package aisec.dest

import rego.v1

app := data.aisec.catalog.apps[input.destination.app_id]

destination := object.union(input.destination, object.filter(app, {"sanction", "region", "trains_on_data"})) if app

else := input.destination
