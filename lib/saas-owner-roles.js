'use strict';

/** Full planner + portal privileges for the tenant purchaser (after active subscription). */
const SAAS_OWNER_ROLES = Object.freeze({
  camera: true,
  vac: true,
  simpleVac: true,
  email: true,
  psrPlanner: true,
  psrViewer: true,
  psrDataEntry: true,
  dataAutoSyncEmployee: true,
  pricingView: true,
  footageView: true,
  jobsiteContactsView: true,
  portalUpload: true,
  portalDownload: true,
  portalEdit: true,
  portalDelete: true
});

/** Self-signup / pre-subscription baseline — no product tools until subscription + login. */
const SAAS_PURCHASER_BASELINE_ROLES = Object.freeze({
  camera: false,
  vac: false,
  simpleVac: false,
  email: false,
  psrPlanner: false,
  psrViewer: false,
  psrDataEntry: false,
  dataAutoSyncEmployee: false,
  pricingView: false,
  footageView: false,
  jobsiteContactsView: false,
  portalUpload: false,
  portalDownload: false,
  portalEdit: false,
  portalDelete: false
});

module.exports = {
  SAAS_OWNER_ROLES,
  SAAS_PURCHASER_BASELINE_ROLES
};
