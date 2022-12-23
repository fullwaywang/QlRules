/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_create
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-create
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_create 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

from Function func, Parameter vfhp_1348, Parameter vfname_1349, Parameter vflen_1349, Parameter vattrs_1349, Parameter vtype_1350, Parameter vrdev_1350, Parameter vresfhp_1350, Parameter vrqstp_1348
where
vfhp_1348.getType().hasName("svc_fh *")
and vfname_1349.getType().hasName("char *")
and vflen_1349.getType().hasName("int")
and vattrs_1349.getType().hasName("nfsd_attrs *")
and vtype_1350.getType().hasName("int")
and vrdev_1350.getType().hasName("dev_t")
and vresfhp_1350.getType().hasName("svc_fh *")
and vrqstp_1348.getType().hasName("svc_rqst *")
and vfhp_1348.getParentScope+() = func
and vfname_1349.getParentScope+() = func
and vflen_1349.getParentScope+() = func
and vattrs_1349.getParentScope+() = func
and vtype_1350.getParentScope+() = func
and vrdev_1350.getParentScope+() = func
and vresfhp_1350.getParentScope+() = func
and vrqstp_1348.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
