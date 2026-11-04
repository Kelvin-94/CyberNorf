-- AlterTable
ALTER TABLE "framework_controls" ADD COLUMN     "position" INTEGER NOT NULL DEFAULT 0;

-- CreateIndex
CREATE INDEX "framework_controls_frameworkId_position_idx" ON "framework_controls"("frameworkId", "position");

-- Backfill the catalog display order. The previous migration inserted the
-- controls of each framework in their canonical order, so the physical row
-- order (ctid) at the time of this migration reproduces the catalog sequence.
-- Fresh databases replay both migrations in order, so the same VALUES apply.
UPDATE "framework_controls" AS c
SET "position" = v."position"
FROM (VALUES
  ('ctl_gdpr_art_5', 1),
  ('ctl_iso27001_a_5_15', 1),
  ('ctl_nistcsf_gv_oc_01', 1),
  ('ctl_pcidss_1_3', 1),
  ('ctl_soc2_cc6_1', 1),
  ('ctl_gdpr_art_6', 2),
  ('ctl_iso27001_a_5_17', 2),
  ('ctl_nistcsf_gv_rr_02', 2),
  ('ctl_pcidss_2_2', 2),
  ('ctl_soc2_cc6_2', 2),
  ('ctl_gdpr_art_25', 3),
  ('ctl_iso27001_a_5_18', 3),
  ('ctl_nistcsf_id_am_01', 3),
  ('ctl_pcidss_3_5_1', 3),
  ('ctl_soc2_cc6_3', 3),
  ('ctl_gdpr_art_28', 4),
  ('ctl_iso27001_a_5_24', 4),
  ('ctl_nistcsf_id_ra_01', 4),
  ('ctl_pcidss_4_2_1', 4),
  ('ctl_soc2_cc6_6', 4),
  ('ctl_gdpr_art_30', 5),
  ('ctl_iso27001_a_5_25', 5),
  ('ctl_nistcsf_id_ra_06', 5),
  ('ctl_pcidss_5_3_1', 5),
  ('ctl_soc2_cc6_7', 5),
  ('ctl_gdpr_art_32', 6),
  ('ctl_iso27001_a_5_26', 6),
  ('ctl_nistcsf_pr_aa_01', 6),
  ('ctl_pcidss_6_3_1', 6),
  ('ctl_soc2_cc7_1', 6),
  ('ctl_gdpr_art_33', 7),
  ('ctl_iso27001_a_6_8', 7),
  ('ctl_nistcsf_pr_aa_03', 7),
  ('ctl_pcidss_7_2_1', 7),
  ('ctl_soc2_cc7_2', 7),
  ('ctl_gdpr_art_34', 8),
  ('ctl_iso27001_a_8_7', 8),
  ('ctl_nistcsf_pr_ps_02', 8),
  ('ctl_pcidss_8_3_1', 8),
  ('ctl_soc2_cc7_3', 8),
  ('ctl_gdpr_art_35', 9),
  ('ctl_iso27001_a_8_8', 9),
  ('ctl_nistcsf_de_cm_01', 9),
  ('ctl_pcidss_10_2_1', 9),
  ('ctl_soc2_cc7_4', 9),
  ('ctl_gdpr_art_15', 10),
  ('ctl_iso27001_a_8_9', 10),
  ('ctl_nistcsf_de_ae_02', 10),
  ('ctl_pcidss_10_4_1', 10),
  ('ctl_soc2_cc8_1', 10),
  ('ctl_gdpr_art_17', 11),
  ('ctl_iso27001_a_8_12', 11),
  ('ctl_nistcsf_rs_ma_01', 11),
  ('ctl_pcidss_11_3_1', 11),
  ('ctl_soc2_a1_2', 11),
  ('ctl_gdpr_art_7', 12),
  ('ctl_iso27001_a_8_15', 12),
  ('ctl_nistcsf_rc_rp_01', 12),
  ('ctl_pcidss_12_10_1', 12),
  ('ctl_soc2_p4_2', 12),
  ('ctl_iso27001_a_8_16', 13)
) AS v("id", "position")
WHERE c."id" = v."id";
