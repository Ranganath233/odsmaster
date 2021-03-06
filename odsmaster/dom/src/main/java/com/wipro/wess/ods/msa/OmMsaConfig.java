package com.wipro.wess.ods.msa;

// Generated Jan 7, 2014 12:15:31 PM by Hibernate Tools 3.2.2.GA

import java.math.BigDecimal;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.jdo.InstanceCallbacks;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdentityType;
import javax.jdo.annotations.Persistent;

import org.apache.isis.applib.DomainObjectContainer;
import org.apache.isis.applib.annotation.Audited;
import org.apache.isis.applib.annotation.Bookmarkable;
import org.apache.isis.applib.annotation.Bulk;
import org.apache.isis.applib.annotation.CssClass;
import org.apache.isis.applib.annotation.Hidden;
import org.apache.isis.applib.annotation.Named;
import org.apache.isis.applib.annotation.ObjectType;
import org.apache.isis.applib.annotation.Optional;
import org.apache.isis.applib.annotation.Title;
import org.apache.isis.applib.annotation.Where;

import com.wipro.wess.ods.organisation.MOrganisation;

/**
 * OmMsaConfig generated by hbm2java
 */
@Named("MSA")
@Bookmarkable
@Audited
@ObjectType("OmMsaConfig")
@javax.jdo.annotations.PersistenceCapable(schema = "gemsods", table = "om_msa_config", objectIdClass = OmMsaConfigPK.class, identityType = IdentityType.APPLICATION)
@javax.jdo.annotations.Queries({
        @javax.jdo.annotations.Query(name = "fetch_OmMsaConfig_by_pk", language = "JDOQL", value = "SELECT "
                + " OmMsaConfig FROM com.wipro.wess.ods.msa.OmMsaConfig OmMsaConfig " + " WHERE msaUid == :msaUid"),
        @javax.jdo.annotations.Query(name = "fetch_msaconfigs_by_user", language = "JPQL", value = "SELECT msa FROM com.wipro.wess.ods.msa.OmMsaConfig msa "
                + " WHERE msa IN ("
                + " SELECT msasitemap.msaUid FROM com.wipro.wess.ods.site.OmMsaSiteMap msasitemap"
                + " JOIN msasitemap.omSite site WHERE EXISTS "
                + " (SELECT 1 FROM com.wipro.wess.pdm.security.OmPermission permission WHERE permission.site = site AND permission IN "
                + " (SELECT "
                + " OmRolesPermissions.permission FROM com.wipro.wess.pdm.security.OmRolesPermissions OmRolesPermissions "
                + " WHERE role IN ( SELECT OmUsersRoles.role FROM com.wipro.wess.pdm.security.OmUsersRoles OmUsersRoles WHERE OmUsersRoles.user.userName = :userName) ) ) ) ") })
public class OmMsaConfig implements java.io.Serializable, InstanceCallbacks {

    /**
	 * 
	 */
    private static final long serialVersionUID = -1581532581067511420L;

    private String msaUid;

    private MOrganisation orgId;

    // private OmSite site;

    private String description;

    private String areaType;

    private BigDecimal overallArea;

    private String contactOp;

    private Integer peopleCount;

    private String msaName;

    private String status;

    private BigDecimal ahThresholdPercent;

    private BigDecimal phThresholdPercent;

    private BigDecimal dlThresholdPercent;

    private BigDecimal expdWeeklyOpHrs;

    private BigDecimal expdWeeklyPsHrs;

    private String subtypeLvl2;

    private String changeBy;

    private Date changeDt;

    Set<OmMsaModeopDef> omMsaModeopDefs = new HashSet<OmMsaModeopDef>(0);

    private String configUser;

    /*
     * private Set<OmOperationalDaysMonth> omOperationalDaysMonths = new HashSet<OmOperationalDaysMonth>(0); private
     * Set<OmMsaModeopDef> omMsaModeopDefs = new HashSet<OmMsaModeopDef>(0); private Set<OmMsaConsStFr> omMsaConsStFrs =
     * new HashSet<OmMsaConsStFr>(0); private Set<OmMsaHierarchyDimensionOld> omMsaHierarchyDimensionOlds = new
     * HashSet<OmMsaHierarchyDimensionOld>(0); private Set<OmMsaSiteMap> omMsaSiteMaps = new HashSet<OmMsaSiteMap>(0);
     * private Set<OmBaselineDefinition> omBaselineDefinitions = new HashSet<OmBaselineDefinition>(0); private
     * Set<OmMsaServiceMap> omMsaServiceMaps = new HashSet<OmMsaServiceMap>(0); private Set<OmMsaConsFr> omMsaConsFrs =
     * new HashSet<OmMsaConsFr>(0); private Set<OmMsaScaMap> omMsaScaMaps = new HashSet<OmMsaScaMap>(0); private
     * Set<OmMsaConsStsubtFr> omMsaConsStsubtFrs = new HashSet<OmMsaConsStsubtFr>(0); private Set<OmMsaRuMap>
     * omMsaRuMaps = new HashSet<OmMsaRuMap>(0);
     */

    public OmMsaConfig() {
    }

    public OmMsaConfig(String msaUid, MOrganisation orgId, String changeBy, Date changeDt) {
        this.msaUid = msaUid;
        this.orgId = orgId;
        this.changeBy = changeBy;
        this.changeDt = changeDt;
    }

    public OmMsaConfig(String msaUid, MOrganisation orgId, String description, String areaType, BigDecimal overallArea,
            String contactOp, Integer peopleCount, String msaName, String status, BigDecimal ahThresholdPercent,
            BigDecimal phThresholdPercent, BigDecimal dlThresholdPercent, BigDecimal expdWeeklyOpHrs,
            BigDecimal expdWeeklyPsHrs, String subtypeLvl2, String changeBy, Date changeDt/*
                                                                                           * , Set <
                                                                                           * OmOperationalDaysMonth >
                                                                                           * omOperationalDaysMonths ,
                                                                                           * Set < OmMsaModeopDef >
                                                                                           * omMsaModeopDefs , Set <
                                                                                           * OmMsaConsStFr >
                                                                                           * omMsaConsStFrs , Set <
                                                                                           * OmMsaHierarchyDimensionOld
                                                                                           * >
                                                                                           * omMsaHierarchyDimensionOlds
                                                                                           * , Set < OmMsaSiteMap >
                                                                                           * omMsaSiteMaps , Set <
                                                                                           * OmBaselineDefinition >
                                                                                           * omBaselineDefinitions , Set
                                                                                           * < OmMsaServiceMap >
                                                                                           * omMsaServiceMaps , Set <
                                                                                           * OmMsaConsFr > omMsaConsFrs
                                                                                           * , Set < OmMsaScaMap >
                                                                                           * omMsaScaMaps , Set <
                                                                                           * OmMsaConsStsubtFr >
                                                                                           * omMsaConsStsubtFrs , Set <
                                                                                           * OmMsaRuMap > omMsaRuMaps
                                                                                           */) {
        this.msaUid = msaUid;
        this.orgId = orgId;
        this.description = description;
        this.areaType = areaType;
        this.overallArea = overallArea;
        this.contactOp = contactOp;
        this.peopleCount = peopleCount;
        this.msaName = msaName;
        this.status = status;
        this.ahThresholdPercent = ahThresholdPercent;
        this.phThresholdPercent = phThresholdPercent;
        this.dlThresholdPercent = dlThresholdPercent;
        this.expdWeeklyOpHrs = expdWeeklyOpHrs;
        this.expdWeeklyPsHrs = expdWeeklyPsHrs;
        this.subtypeLvl2 = subtypeLvl2;
        this.changeBy = changeBy;
        this.changeDt = changeDt;
        /*
         * this.omOperationalDaysMonths = omOperationalDaysMonths; this.omMsaModeopDefs = omMsaModeopDefs;
         * this.omMsaConsStFrs = omMsaConsStFrs; this.omMsaHierarchyDimensionOlds = omMsaHierarchyDimensionOlds;
         * this.omMsaSiteMaps = omMsaSiteMaps; this.omBaselineDefinitions = omBaselineDefinitions; this.omMsaServiceMaps
         * = omMsaServiceMaps; this.omMsaConsFrs = omMsaConsFrs; this.omMsaScaMaps = omMsaScaMaps;
         * this.omMsaConsStsubtFrs = omMsaConsStsubtFrs; this.omMsaRuMaps = omMsaRuMaps;
         */
    }

    @javax.jdo.annotations.Column(allowsNull = "false", name = "msa_uid")
    @Title
    @Persistent(primaryKey = "true")
    public String getMsaUid() {
        return this.msaUid;
    }

    public void setMsaUid(String msaUid) {
        this.msaUid = msaUid;
    }

    /*
     * @Columns(value = { @Column(allowsNull = "false", name = "org_id"), @Column(name = "site_id") })
     * @Optional public OmSite getSite() { return site; } public void setSite(OmSite site) { this.site = site; }
     */

    @Column(allowsNull = "false", name = "org_id")
    public MOrganisation getOrgId() {
        return this.orgId;
    }

    public void setOrgId(MOrganisation orgId) {
        this.orgId = orgId;
    }

    @Column(name = "description")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Column(name = "area_type")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public String getAreaType() {
        return this.areaType;
    }

    public void setAreaType(String areaType) {
        this.areaType = areaType;
    }

    @Column(name = "overall_area")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public BigDecimal getOverallArea() {
        return this.overallArea;
    }

    public void setOverallArea(BigDecimal overallArea) {
        this.overallArea = overallArea;
    }

    @Column(name = "contact_op")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public String getContactOp() {
        return this.contactOp;
    }

    public void setContactOp(String contactOp) {
        this.contactOp = contactOp;
    }

    @Column(name = "people_count")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public Integer getPeopleCount() {
        return this.peopleCount;
    }

    public void setPeopleCount(Integer peopleCount) {
        this.peopleCount = peopleCount;
    }

    @Column(name = "msa_name")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public String getMsaName() {
        return this.msaName;
    }

    public void setMsaName(String msaName) {
        this.msaName = msaName;
    }

    @Column(name = "status")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @Column(name = "ah_threshold_percent")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public BigDecimal getAhThresholdPercent() {
        return this.ahThresholdPercent;
    }

    public void setAhThresholdPercent(BigDecimal ahThresholdPercent) {
        this.ahThresholdPercent = ahThresholdPercent;
    }

    @Column(name = "ph_threshold_percent")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public BigDecimal getPhThresholdPercent() {
        return this.phThresholdPercent;
    }

    public void setPhThresholdPercent(BigDecimal phThresholdPercent) {
        this.phThresholdPercent = phThresholdPercent;
    }

    @Column(name = "dl_threshold_percent")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public BigDecimal getDlThresholdPercent() {
        return this.dlThresholdPercent;
    }

    public void setDlThresholdPercent(BigDecimal dlThresholdPercent) {
        this.dlThresholdPercent = dlThresholdPercent;
    }

    @Column(name = "expd_weekly_op_hrs")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public BigDecimal getExpdWeeklyOpHrs() {
        return this.expdWeeklyOpHrs;
    }

    public void setExpdWeeklyOpHrs(BigDecimal expdWeeklyOpHrs) {
        this.expdWeeklyOpHrs = expdWeeklyOpHrs;
    }

    @Column(name = "expd_weekly_ps_hrs")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public BigDecimal getExpdWeeklyPsHrs() {
        return this.expdWeeklyPsHrs;
    }

    public void setExpdWeeklyPsHrs(BigDecimal expdWeeklyPsHrs) {
        this.expdWeeklyPsHrs = expdWeeklyPsHrs;
    }

    @Column(name = "subtype_lvl2")
    @Optional
    @Hidden(where = Where.ALL_TABLES)
    public String getSubtypeLvl2() {
        return this.subtypeLvl2;
    }

    public void setSubtypeLvl2(String subtypeLvl2) {
        this.subtypeLvl2 = subtypeLvl2;
    }

    @Column(allowsNull = "false", name = "change_by")
    @Hidden(where = Where.OBJECT_FORMS)
    public String getChangeBy() {
        return this.changeBy;
    }

    public void setChangeBy(String changeBy) {
        this.changeBy = changeBy;
    }

    @Column(allowsNull = "false", name = "change_dt")
    @Hidden(where = Where.OBJECT_FORMS)
    public Date getChangeDt() {
        return this.changeDt;
    }

    public void setChangeDt(Date changeDt) {
        this.changeDt = changeDt;
    }

    /*
     * public Set<OmOperationalDaysMonth> getOmOperationalDaysMonths() { return this.omOperationalDaysMonths; } public
     * void setOmOperationalDaysMonths( Set<OmOperationalDaysMonth> omOperationalDaysMonths) {
     * this.omOperationalDaysMonths = omOperationalDaysMonths; } public Set<OmMsaModeopDef> getOmMsaModeopDefs() {
     * return this.omMsaModeopDefs; } public void setOmMsaModeopDefs(Set<OmMsaModeopDef> omMsaModeopDefs) {
     * this.omMsaModeopDefs = omMsaModeopDefs; } public Set<OmMsaConsStFr> getOmMsaConsStFrs() { return
     * this.omMsaConsStFrs; } public void setOmMsaConsStFrs(Set<OmMsaConsStFr> omMsaConsStFrs) { this.omMsaConsStFrs =
     * omMsaConsStFrs; } public Set<OmMsaHierarchyDimensionOld> getOmMsaHierarchyDimensionOlds() { return
     * this.omMsaHierarchyDimensionOlds; } public void setOmMsaHierarchyDimensionOlds( Set<OmMsaHierarchyDimensionOld>
     * omMsaHierarchyDimensionOlds) { this.omMsaHierarchyDimensionOlds = omMsaHierarchyDimensionOlds; } public
     * Set<OmMsaSiteMap> getOmMsaSiteMaps() { return this.omMsaSiteMaps; } public void
     * setOmMsaSiteMaps(Set<OmMsaSiteMap> omMsaSiteMaps) { this.omMsaSiteMaps = omMsaSiteMaps; } public
     * Set<OmBaselineDefinition> getOmBaselineDefinitions() { return this.omBaselineDefinitions; } public void
     * setOmBaselineDefinitions( Set<OmBaselineDefinition> omBaselineDefinitions) { this.omBaselineDefinitions =
     * omBaselineDefinitions; } public Set<OmMsaServiceMap> getOmMsaServiceMaps() { return this.omMsaServiceMaps; }
     * public void setOmMsaServiceMaps(Set<OmMsaServiceMap> omMsaServiceMaps) { this.omMsaServiceMaps =
     * omMsaServiceMaps; } public Set<OmMsaConsFr> getOmMsaConsFrs() { return this.omMsaConsFrs; } public void
     * setOmMsaConsFrs(Set<OmMsaConsFr> omMsaConsFrs) { this.omMsaConsFrs = omMsaConsFrs; } public Set<OmMsaScaMap>
     * getOmMsaScaMaps() { return this.omMsaScaMaps; } public void setOmMsaScaMaps(Set<OmMsaScaMap> omMsaScaMaps) {
     * this.omMsaScaMaps = omMsaScaMaps; } public Set<OmMsaConsStsubtFr> getOmMsaConsStsubtFrs() { return
     * this.omMsaConsStsubtFrs; } public void setOmMsaConsStsubtFrs(Set<OmMsaConsStsubtFr> omMsaConsStsubtFrs) {
     * this.omMsaConsStsubtFrs = omMsaConsStsubtFrs; } public Set<OmMsaRuMap> getOmMsaRuMaps() { return
     * this.omMsaRuMaps; } public void setOmMsaRuMaps(Set<OmMsaRuMap> omMsaRuMaps) { this.omMsaRuMaps = omMsaRuMaps; }
     */

    @Persistent(mappedBy = "omMsaConfig", dependentElement = "true")
    public Set<OmMsaModeopDef> getOmMsaModeopDefs() {
        return this.omMsaModeopDefs;
    }

    public void setOmMsaModeopDefs(Set<OmMsaModeopDef> omMsaModeopDefs) {
        this.omMsaModeopDefs = omMsaModeopDefs;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((msaUid == null) ? 0 : msaUid.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        OmMsaConfig other = (OmMsaConfig) obj;
        if (msaUid == null) {
            if (other.msaUid != null)
                return false;
        } else if (!msaUid.equals(other.msaUid))
            return false;
        return true;
    }

    @Column(name = "config_user")
    @Hidden(where = Where.EVERYWHERE)
    public String getConfigUser() {
        return configUser;
    }

    public void setConfigUser(String configUser) {
        this.configUser = configUser;
    }

    private DomainObjectContainer container;

    public void injectDomainObjectContainer(DomainObjectContainer container) {
        this.container = container;
    }

    public void jdoPostLoad() {
    }

    public void jdoPreClear() {
    }

    public void jdoPreStore() {
        this.setChangeBy(this.container.getUser().getName());
        this.setChangeDt(new Date());
        this.setConfigUser(this.container.getUser().getName());
    }

    public void jdoPreDelete() {
    }

    private OmMsaConfigService msaConfigService;

    public void injectOmMsaConfigService(OmMsaConfigService msaConfigService) {
        this.msaConfigService = msaConfigService;
    }

    @Bulk
    @CssClass("x-caution")
    public List<OmMsaConfig> delete() {
        this.container.removeIfNotAlready(this);
        this.container.informUser("Deleted " + container.titleOf(this));
        return this.msaConfigService.listAllMsaConfigs();

    }
}
