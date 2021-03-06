package com.wipro.wess.ods.uom;

import java.util.StringTokenizer;

import com.wipro.wess.ods.masterconfig.MPointlistPK;
import com.wipro.wess.ods.organisation.OrganisationPK;
import com.wipro.wess.ods.upload.ProvisioningConstants;
import com.wipro.wess.ods.utils.OmUtil;

// Generated Jan 7, 2014 12:15:31 PM by Hibernate Tools 3.2.2.GA

/**
 * OmPointlistCountryPolicyId generated by hbm2java
 */
public class OmPointlistCountryPolicyPK implements java.io.Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -2672261623083245930L;

    public OrganisationPK orgId;

    public String locCountryUid;

    public MPointlistPK pointList;

    public OmPointlistCountryPolicyPK() {
    }

    public OmPointlistCountryPolicyPK(OrganisationPK orgId, String locCountryUid, MPointlistPK pointList) {
        this.orgId = orgId;
        this.locCountryUid = locCountryUid;
        this.pointList = pointList;
    }

    public OmPointlistCountryPolicyPK(String key) {
        StringTokenizer token = new StringTokenizer(OmUtil.decode(key), ProvisioningConstants.DOMAIN_OBJ_SEPERATOR);
        this.orgId = new OrganisationPK(token.nextToken());
        this.locCountryUid = token.nextToken();
        this.pointList = new MPointlistPK(token.nextToken());
    }

    @Override
    public String toString() {
        return OmUtil.encode("" + this.orgId.toString() + ProvisioningConstants.DOMAIN_OBJ_SEPERATOR
                + this.locCountryUid + ProvisioningConstants.DOMAIN_OBJ_SEPERATOR + this.pointList.toString());
    }

    public OrganisationPK getOrgId() {
        return this.orgId;
    }

    public void setOrgId(OrganisationPK orgId) {
        this.orgId = orgId;
    }

    public String getLocCountryUid() {
        return this.locCountryUid;
    }

    public void setLocCountryUid(String locCountryUid) {
        this.locCountryUid = locCountryUid;
    }

    public MPointlistPK getPointList() {
        return pointList;
    }

    public void setPointList(MPointlistPK pointList) {
        this.pointList = pointList;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((locCountryUid == null) ? 0 : locCountryUid.hashCode());
        result = prime * result + ((orgId == null) ? 0 : orgId.hashCode());
        result = prime * result + ((pointList == null) ? 0 : pointList.hashCode());
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
        OmPointlistCountryPolicyPK other = (OmPointlistCountryPolicyPK) obj;
        if (locCountryUid == null) {
            if (other.locCountryUid != null)
                return false;
        } else if (!locCountryUid.equals(other.locCountryUid))
            return false;
        if (orgId == null) {
            if (other.orgId != null)
                return false;
        } else if (!orgId.equals(other.orgId))
            return false;
        if (pointList == null) {
            if (other.pointList != null)
                return false;
        } else if (!pointList.equals(other.pointList))
            return false;
        return true;
    }

}
