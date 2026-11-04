-- CreateEnum
CREATE TYPE "ControlStatus" AS ENUM ('NOT_STARTED', 'IN_PROGRESS', 'PARTIAL', 'IMPLEMENTED', 'NOT_APPLICABLE');

-- CreateEnum
CREATE TYPE "EvidenceKind" AS ENUM ('FINDING', 'INCIDENT', 'ASSET', 'REFERENCE');

-- CreateTable
CREATE TABLE "frameworks" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "frameworks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "framework_controls" (
    "id" TEXT NOT NULL,
    "frameworkId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "category" TEXT,
    "weight" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "framework_controls_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organization_frameworks" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "frameworkId" TEXT NOT NULL,
    "adoptedById" TEXT,
    "adoptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "targetDate" TIMESTAMP(3),

    CONSTRAINT "organization_frameworks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organization_controls" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "organizationFrameworkId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "status" "ControlStatus" NOT NULL DEFAULT 'NOT_STARTED',
    "ownerId" TEXT,
    "updatedById" TEXT,
    "notes" TEXT,
    "lastReviewedAt" TIMESTAMP(3),
    "nextReviewAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "organization_controls_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "control_evidence" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "organizationControlId" TEXT NOT NULL,
    "kind" "EvidenceKind" NOT NULL,
    "findingId" TEXT,
    "incidentId" TEXT,
    "assetId" TEXT,
    "reference" TEXT,
    "note" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "control_evidence_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "frameworks_code_key" ON "frameworks"("code");

-- CreateIndex
CREATE INDEX "framework_controls_frameworkId_category_idx" ON "framework_controls"("frameworkId", "category");

-- CreateIndex
CREATE UNIQUE INDEX "framework_controls_frameworkId_code_key" ON "framework_controls"("frameworkId", "code");

-- CreateIndex
CREATE INDEX "organization_frameworks_organizationId_idx" ON "organization_frameworks"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "organization_frameworks_organizationId_frameworkId_key" ON "organization_frameworks"("organizationId", "frameworkId");

-- CreateIndex
CREATE INDEX "organization_controls_organizationId_status_idx" ON "organization_controls"("organizationId", "status");

-- CreateIndex
CREATE INDEX "organization_controls_organizationId_ownerId_idx" ON "organization_controls"("organizationId", "ownerId");

-- CreateIndex
CREATE UNIQUE INDEX "organization_controls_organizationFrameworkId_controlId_key" ON "organization_controls"("organizationFrameworkId", "controlId");

-- CreateIndex
CREATE INDEX "control_evidence_organizationControlId_createdAt_idx" ON "control_evidence"("organizationControlId", "createdAt");

-- CreateIndex
CREATE INDEX "control_evidence_organizationId_idx" ON "control_evidence"("organizationId");

-- AddForeignKey
ALTER TABLE "framework_controls" ADD CONSTRAINT "framework_controls_frameworkId_fkey" FOREIGN KEY ("frameworkId") REFERENCES "frameworks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_frameworks" ADD CONSTRAINT "organization_frameworks_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_frameworks" ADD CONSTRAINT "organization_frameworks_frameworkId_fkey" FOREIGN KEY ("frameworkId") REFERENCES "frameworks"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_frameworks" ADD CONSTRAINT "organization_frameworks_adoptedById_fkey" FOREIGN KEY ("adoptedById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_controls" ADD CONSTRAINT "organization_controls_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_controls" ADD CONSTRAINT "organization_controls_organizationFrameworkId_fkey" FOREIGN KEY ("organizationFrameworkId") REFERENCES "organization_frameworks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_controls" ADD CONSTRAINT "organization_controls_controlId_fkey" FOREIGN KEY ("controlId") REFERENCES "framework_controls"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_controls" ADD CONSTRAINT "organization_controls_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_controls" ADD CONSTRAINT "organization_controls_updatedById_fkey" FOREIGN KEY ("updatedById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "control_evidence" ADD CONSTRAINT "control_evidence_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "control_evidence" ADD CONSTRAINT "control_evidence_organizationControlId_fkey" FOREIGN KEY ("organizationControlId") REFERENCES "organization_controls"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "control_evidence" ADD CONSTRAINT "control_evidence_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "control_evidence" ADD CONSTRAINT "control_evidence_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "control_evidence" ADD CONSTRAINT "control_evidence_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "control_evidence" ADD CONSTRAINT "control_evidence_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Compliance catalog
-- ---------------------------------------------------------------------------

-- Exactly one evidence target must be set, so a row can never claim two
-- sources or none. The application validates this too; the constraint protects
-- against direct SQL and future code paths.
ALTER TABLE "control_evidence"
  ADD CONSTRAINT "control_evidence_single_target_check" CHECK (
    ("kind" = 'FINDING' AND "findingId" IS NOT NULL AND "incidentId" IS NULL AND "assetId" IS NULL AND "reference" IS NULL) OR
    ("kind" = 'INCIDENT' AND "incidentId" IS NOT NULL AND "findingId" IS NULL AND "assetId" IS NULL AND "reference" IS NULL) OR
    ("kind" = 'ASSET' AND "assetId" IS NOT NULL AND "findingId" IS NULL AND "incidentId" IS NULL AND "reference" IS NULL) OR
    ("kind" = 'REFERENCE' AND "reference" IS NOT NULL AND "findingId" IS NULL AND "incidentId" IS NULL AND "assetId" IS NULL)
  );

-- A control may only be attested when it has been reviewed at least once.
ALTER TABLE "organization_controls"
  ADD CONSTRAINT "organization_controls_attested_reviewed_check" CHECK (
    "status" NOT IN ('IMPLEMENTED', 'PARTIAL') OR "lastReviewedAt" IS NOT NULL
  );

-- Curated subset of each standard. The catalog is shared by every tenant and
-- is intentionally not editable from the application.
INSERT INTO "frameworks" ("id", "code", "name", "version", "description") VALUES ('fw_soc2', 'SOC2', 'SOC 2', '2017 TSC with 2022 points of focus', 'Trust Services Criteria for service organizations. The catalog covers the Security (common criteria) series plus availability and privacy controls most often requested by customers.');
INSERT INTO "frameworks" ("id", "code", "name", "version", "description") VALUES ('fw_iso27001', 'ISO27001', 'ISO/IEC 27001', '2022 Annex A', 'Annex A controls from ISO/IEC 27001:2022 covering organizational, people and technological controls that a certification audit samples.');
INSERT INTO "frameworks" ("id", "code", "name", "version", "description") VALUES ('fw_nist_csf', 'NISTCSF', 'NIST Cybersecurity Framework', '2.0', 'Subcategories from the CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) that map directly to SOC operations.');
INSERT INTO "frameworks" ("id", "code", "name", "version", "description") VALUES ('fw_pci_dss', 'PCIDSS', 'PCI DSS', '4.0.1', 'Requirements covering the cardholder data environment that are commonly evidenced from vulnerability management, access control and logging.');
INSERT INTO "frameworks" ("id", "code", "name", "version", "description") VALUES ('fw_gdpr', 'GDPR', 'GDPR', 'Regulation (EU) 2016/679', 'Articles that govern how personal data is processed, secured and reported on. The catalog supports demonstrating accountability, not legal compliance advice.');

INSERT INTO "framework_controls" ("id", "frameworkId", "code", "title", "description", "category", "weight") VALUES
  ('ctl_soc2_cc6_1', 'fw_soc2', 'CC6.1', 'Logical and physical access controls', 'Access to software, infrastructure and data is restricted to authorized users through defined logical access controls.', 'Security', 3),
  ('ctl_soc2_cc6_2', 'fw_soc2', 'CC6.2', 'User registration and de-provisioning', 'Users are registered before access is granted and access is removed when it is no longer required.', 'Security', 3),
  ('ctl_soc2_cc6_3', 'fw_soc2', 'CC6.3', 'Role-based access and least privilege', 'Access is authorized based on roles and least privilege, and reviewed periodically.', 'Security', 3),
  ('ctl_soc2_cc6_6', 'fw_soc2', 'CC6.6', 'Protection against external threats', 'Boundary protection restricts traffic and blocks unauthorized external access.', 'Security', 2),
  ('ctl_soc2_cc6_7', 'fw_soc2', 'CC6.7', 'Restricted data transmission and movement', 'Data in transit is protected and movement of data is restricted to authorized channels.', 'Security', 2),
  ('ctl_soc2_cc7_1', 'fw_soc2', 'CC7.1', 'Vulnerability and configuration monitoring', 'The organization detects configuration changes and vulnerabilities in infrastructure and software.', 'Security', 2),
  ('ctl_soc2_cc7_2', 'fw_soc2', 'CC7.2', 'Monitoring for anomalies', 'System components are monitored to detect anomalies that indicate malicious acts or incidents.', 'Security', 2),
  ('ctl_soc2_cc7_3', 'fw_soc2', 'CC7.3', 'Evaluation of security events', 'Security events are evaluated to determine whether they represent incidents.', 'Security', 2),
  ('ctl_soc2_cc7_4', 'fw_soc2', 'CC7.4', 'Incident response', 'Incidents are contained, responded to and communicated according to a defined process.', 'Security', 2),
  ('ctl_soc2_cc8_1', 'fw_soc2', 'CC8.1', 'Change management', 'Changes to infrastructure and software are authorized, tested and approved before deployment.', 'Security', 2),
  ('ctl_soc2_a1_2', 'fw_soc2', 'A1.2', 'Availability: backup and recovery', 'Data is backed up and restoration is tested to meet availability commitments.', 'Availability', 2),
  ('ctl_soc2_p4_2', 'fw_soc2', 'P4.2', 'Privacy: use consistent with notice', 'Personal information is collected and used only as described in the privacy notice.', 'Privacy', 1);
INSERT INTO "framework_controls" ("id", "frameworkId", "code", "title", "description", "category", "weight") VALUES
  ('ctl_iso27001_a_5_15', 'fw_iso27001', 'A.5.15', 'Access control', 'Rules to control physical and logical access are established and applied based on business and security requirements.', 'Organizational', 2),
  ('ctl_iso27001_a_5_17', 'fw_iso27001', 'A.5.17', 'Authentication information', 'Authentication information is allocated and managed through a controlled process.', 'Organizational', 2),
  ('ctl_iso27001_a_5_18', 'fw_iso27001', 'A.5.18', 'Access rights', 'Access rights are provisioned, reviewed and removed according to the access control policy.', 'Organizational', 3),
  ('ctl_iso27001_a_5_24', 'fw_iso27001', 'A.5.24', 'Incident management planning', 'The organization plans and prepares for managing information security incidents.', 'Organizational', 2),
  ('ctl_iso27001_a_5_25', 'fw_iso27001', 'A.5.25', 'Assessment of security events', 'Information security events are assessed and classified as incidents or not.', 'Organizational', 2),
  ('ctl_iso27001_a_5_26', 'fw_iso27001', 'A.5.26', 'Response to incidents', 'Information security incidents are responded to according to documented procedures.', 'Organizational', 2),
  ('ctl_iso27001_a_6_8', 'fw_iso27001', 'A.6.8', 'Event reporting', 'A mechanism exists for personnel to report observed or suspected security events promptly.', 'People', 1),
  ('ctl_iso27001_a_8_7', 'fw_iso27001', 'A.8.7', 'Protection against malware', 'Protection against malware is implemented and supported by user awareness.', 'Technological', 1),
  ('ctl_iso27001_a_8_8', 'fw_iso27001', 'A.8.8', 'Management of technical vulnerabilities', 'Technical vulnerabilities are identified, evaluated and remediated in a timely manner.', 'Technological', 3),
  ('ctl_iso27001_a_8_9', 'fw_iso27001', 'A.8.9', 'Configuration management', 'Configurations, including security configurations, are established and monitored.', 'Technological', 2),
  ('ctl_iso27001_a_8_12', 'fw_iso27001', 'A.8.12', 'Data leakage prevention', 'Data leakage prevention measures are applied to systems handling sensitive information.', 'Technological', 2),
  ('ctl_iso27001_a_8_15', 'fw_iso27001', 'A.8.15', 'Logging', 'Event logs are produced, stored, protected and analyzed.', 'Technological', 2),
  ('ctl_iso27001_a_8_16', 'fw_iso27001', 'A.8.16', 'Monitoring activities', 'Networks, systems and applications are monitored for anomalous behaviour.', 'Technological', 2);
INSERT INTO "framework_controls" ("id", "frameworkId", "code", "title", "description", "category", "weight") VALUES
  ('ctl_nistcsf_gv_oc_01', 'fw_nist_csf', 'GV.OC-01', 'Organizational context understood', 'The organizational mission is understood and informs cybersecurity risk management.', 'GOVERN', 1),
  ('ctl_nistcsf_gv_rr_02', 'fw_nist_csf', 'GV.RR-02', 'Roles and responsibilities', 'Roles, responsibilities and authorities related to cybersecurity risk are established, communicated and enforced.', 'GOVERN', 2),
  ('ctl_nistcsf_id_am_01', 'fw_nist_csf', 'ID.AM-01', 'Asset inventories', 'Inventories of hardware managed by the organization are maintained.', 'IDENTIFY', 3),
  ('ctl_nistcsf_id_ra_01', 'fw_nist_csf', 'ID.RA-01', 'Vulnerabilities identified', 'Vulnerabilities in assets are identified, validated and recorded.', 'IDENTIFY', 3),
  ('ctl_nistcsf_id_ra_06', 'fw_nist_csf', 'ID.RA-06', 'Risk responses prioritized', 'Risk responses are chosen, prioritized, planned, tracked and communicated.', 'IDENTIFY', 2),
  ('ctl_nistcsf_pr_aa_01', 'fw_nist_csf', 'PR.AA-01', 'Identity and credential management', 'Identities and credentials for authorized users, services and hardware are managed.', 'PROTECT', 3),
  ('ctl_nistcsf_pr_aa_03', 'fw_nist_csf', 'PR.AA-03', 'Authentication', 'Users, services and hardware are authenticated.', 'PROTECT', 3),
  ('ctl_nistcsf_pr_ps_02', 'fw_nist_csf', 'PR.PS-02', 'Software maintenance', 'Software is maintained, replaced and removed commensurate with risk.', 'PROTECT', 2),
  ('ctl_nistcsf_de_cm_01', 'fw_nist_csf', 'DE.CM-01', 'Network monitoring', 'Networks and network services are monitored to find potentially adverse events.', 'DETECT', 2),
  ('ctl_nistcsf_de_ae_02', 'fw_nist_csf', 'DE.AE-02', 'Adverse event analysis', 'Potentially adverse events are analyzed to better understand associated activities.', 'DETECT', 2),
  ('ctl_nistcsf_rs_ma_01', 'fw_nist_csf', 'RS.MA-01', 'Incident response execution', 'The incident response plan is executed in coordination with relevant third parties once an incident is declared.', 'RESPOND', 3),
  ('ctl_nistcsf_rc_rp_01', 'fw_nist_csf', 'RC.RP-01', 'Recovery plan execution', 'The recovery portion of the incident response plan is executed once initiated from the incident response process.', 'RECOVER', 2);
INSERT INTO "framework_controls" ("id", "frameworkId", "code", "title", "description", "category", "weight") VALUES
  ('ctl_pcidss_1_3', 'fw_pci_dss', '1.3', 'Network access to the CDE restricted', 'Network access to and from the cardholder data environment is restricted to only what is necessary.', 'Network security', 2),
  ('ctl_pcidss_2_2', 'fw_pci_dss', '2.2', 'Secure configuration standards', 'Configuration standards are developed, implemented and maintained for all system components.', 'Secure configuration', 2),
  ('ctl_pcidss_3_5_1', 'fw_pci_dss', '3.5.1', 'PAN rendered unreadable', 'Primary account numbers are rendered unreadable anywhere they are stored.', 'Data protection', 3),
  ('ctl_pcidss_4_2_1', 'fw_pci_dss', '4.2.1', 'Strong cryptography for PAN in transit', 'Strong cryptography and security protocols protect PAN during transmission over open, public networks.', 'Data protection', 3),
  ('ctl_pcidss_5_3_1', 'fw_pci_dss', '5.3.1', 'Anti-malware solution deployed', 'An anti-malware solution is deployed on system components where malware is commonly expected.', 'Malware protection', 1),
  ('ctl_pcidss_6_3_1', 'fw_pci_dss', '6.3.1', 'Security vulnerabilities identified and addressed', 'Security vulnerabilities are identified and addressed through a defined process.', 'Secure development', 3),
  ('ctl_pcidss_7_2_1', 'fw_pci_dss', '7.2.1', 'Access restricted by job function', 'Access to system components and data is appropriately defined and assigned by job function.', 'Access control', 3),
  ('ctl_pcidss_8_3_1', 'fw_pci_dss', '8.3.1', 'Strong authentication for users', 'All user access to system components is authenticated through at least one authentication factor.', 'Identity', 3),
  ('ctl_pcidss_10_2_1', 'fw_pci_dss', '10.2.1', 'Audit logs enabled', 'Audit logs are enabled and active for all system components and cardholder data.', 'Logging and monitoring', 2),
  ('ctl_pcidss_10_4_1', 'fw_pci_dss', '10.4.1', 'Daily log review', 'The following audit logs are reviewed at least once daily for anomalies or suspicious activity.', 'Logging and monitoring', 2),
  ('ctl_pcidss_11_3_1', 'fw_pci_dss', '11.3.1', 'Vulnerability scans performed', 'Internal vulnerability scans are performed at the required frequency and findings are remediated.', 'Security testing', 2),
  ('ctl_pcidss_12_10_1', 'fw_pci_dss', '12.10.1', 'Incident response plan', 'An incident response plan exists and is ready to be activated in the event of a suspected or confirmed security incident.', 'Incident response', 2);
INSERT INTO "framework_controls" ("id", "frameworkId", "code", "title", "description", "category", "weight") VALUES
  ('ctl_gdpr_art_5', 'fw_gdpr', 'Art. 5', 'Principles relating to processing', 'Personal data is processed lawfully, fairly, transparently and limited to what is necessary.', 'Principles', 3),
  ('ctl_gdpr_art_6', 'fw_gdpr', 'Art. 6', 'Lawfulness of processing', 'A lawful basis is identified and documented for each processing activity.', 'Principles', 3),
  ('ctl_gdpr_art_25', 'fw_gdpr', 'Art. 25', 'Data protection by design', 'Data protection is designed into processing activities and applied by default.', 'Accountability', 2),
  ('ctl_gdpr_art_28', 'fw_gdpr', 'Art. 28', 'Processor agreements', 'Processors are bound by contracts that impose the required data protection obligations.', 'Accountability', 2),
  ('ctl_gdpr_art_30', 'fw_gdpr', 'Art. 30', 'Records of processing', 'Records of processing activities are maintained and made available to the supervisory authority on request.', 'Accountability', 2),
  ('ctl_gdpr_art_32', 'fw_gdpr', 'Art. 32', 'Security of processing', 'Technical and organizational measures protect personal data against unauthorized access, loss or alteration.', 'Security', 3),
  ('ctl_gdpr_art_33', 'fw_gdpr', 'Art. 33', 'Breach notification to authority', 'Personal data breaches are notified to the supervisory authority without undue delay and within 72 hours where feasible.', 'Incident response', 3),
  ('ctl_gdpr_art_34', 'fw_gdpr', 'Art. 34', 'Communication to data subjects', 'Data subjects are informed without undue delay when a breach is likely to result in a high risk.', 'Incident response', 2),
  ('ctl_gdpr_art_35', 'fw_gdpr', 'Art. 35', 'Data protection impact assessment', 'A DPIA is carried out before processing that is likely to result in a high risk to rights and freedoms.', 'Risk', 2),
  ('ctl_gdpr_art_15', 'fw_gdpr', 'Art. 15', 'Right of access', 'Data subjects can obtain confirmation and a copy of the personal data undergoing processing.', 'Data subject rights', 2),
  ('ctl_gdpr_art_17', 'fw_gdpr', 'Art. 17', 'Right to erasure', 'Personal data is erased without undue delay where a ground for erasure applies.', 'Data subject rights', 2),
  ('ctl_gdpr_art_7', 'fw_gdpr', 'Art. 7', 'Conditions for consent', 'Where consent is the basis, the controller can demonstrate that the data subject consented.', 'Principles', 1);
