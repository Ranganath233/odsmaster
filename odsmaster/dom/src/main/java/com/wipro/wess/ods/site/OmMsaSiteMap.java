package com.wipro.wess.ods.site;

// Generated Jan 7, 2014 12:15:31 PM by Hibernate Tools 3.2.2.GA

import java.util.Date;

import javax.jdo.InstanceCallbacks;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Columns;
import javax.jdo.annotations.IdentityType;
import javax.jdo.annotations.Persistent;

import org.apache.isis.applib.DomainObjectContainer;
import org.apache.isis.applib.annotation.Audited;
import org.apache.isis.applib.annotation.Bookmarkable;
import org.apache.isis.applib.annotation.Hidden;
import org.apache.isis.applib.annotation.Named;
import org.apache.isis.applib.annotation.ObjectType;
import org.apache.isis.applib.annotation.Optional;
import org.apache.isis.applib.annotation.Title;
import org.apache.isis.applib.annotation.Where;

import com.wipro.wess.ods.msa.OmMsaConfig;

/**
 * OmMsaSiteMap generated by hbm2java
 */
@Named("MSA Site")
@Bookmarkable
@Audited
@ObjectType("OmMsaSiteMap")
@javax.jdo.annotations.PersistenceCapable(schema = "gemsods", table = "om_msa_site_map", objectIdClass = OmMsaSiteMapPK.class, identityType = IdentityType.APPLICATION)
@javax.jdo.annotations.Queries({ @javax.jdo.annotations.Query(name = "fetch_msaconfigs_from_msasitemap_by_user", language = "JPQL", value = "SELECT msa.msaUid FROM com.wipro.wess.ods.site.OmMsaSiteMap msa "
        + " JOIN msa.omSite site WHERE EXISTS "
        + " (SELECT 1 FROM com.wipro.wess.pdm.security.OmPermission permission WHERE permission.site = site AND permission IN "
        + " (SELECT "
        + " OmRolesPermissions.permission FROM com.wipro.wess.pdm.security.OmRolesPermissions OmRolesPermissions "
        + " WHERE role IN ( SELECT OmUsersRoles.role FROM com.wipro.wess.pdm.security.OmUsersRoles OmUsersRoles WHERE OmUsersRoles.user.userName = :userName) ) ) ") })
public class OmMsaSiteMap implements java.io.Serializable, InstanceCallbacks {

    /**
	 * 
	 */
    private static final long serialVersionUID = 8084976414377423556L;

    private OmMsaConfig msaUid;

    private OmSite omSite;

    private String changeBy;

    private Date changeDt;
    
    private String configUser;

    public OmMsaSiteMap() {
    }

    public OmMsaSiteMap(OmMsaConfig msaUid, OmSite omSite, String changeBy, Date changeDt) {
        this.msaUid = msaUid;
        this.omSite = omSite;
        this.changeBy = changeBy;
        this.changeDt = changeDt;
    }

    @Persistent(primaryKey = "true", dependent = "false")
    @Column(allowsNull = "false", name = "msa_uid")
    @Title
    public OmMsaConfig getMsaUid() {
        return this.msaUid;
    }

    public void setMsaUid(OmMsaConfig msaUid) {
        this.msaUid = msaUid;
    }

    @Columns(value = { @Column(allowsNull = "false", name = "site_id", target = "site_id"),
            @Column(allowsNull = "false", name = "org_id", target = "org_id") })
    @Optional
    public OmSite getOmSite() {
        return this.omSite;
    }

    public void setOmSite(OmSite omSite) {
        this.omSite = omSite;
    }

    @Column(allowsNull = "false", name = "change_by")
    public String getChangeBy() {
        return this.changeBy;
    }

    public void setChangeBy(String changeBy) {
        this.changeBy = changeBy;
    }

    @Column(allowsNull = "false", name = "change_dt")
    public Date getChangeDt() {
        return this.changeDt;
    }

    public void setChangeDt(Date changeDt) {
        this.changeDt = changeDt;
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

    public void injectDomainObjectContainer(final DomainObjectContainer container) {
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

}