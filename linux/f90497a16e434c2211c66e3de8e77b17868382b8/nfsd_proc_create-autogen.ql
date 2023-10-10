/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_proc_create
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-proc-create
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_proc_create 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vargp_261, Variable vdirfhp_263, Variable vnewfhp_264, Variable vattrs_266, Variable vtype_271, Variable vrdev_273, Parameter vrqstp_259) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="name"
		and target_0.getQualifier().(VariableAccess).getTarget()=vargp_261
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("nfsd_create_locked")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrqstp_259
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdirfhp_263
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3) instanceof PointerFieldAccess
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vattrs_266
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vtype_271
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vrdev_273
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vnewfhp_264)
}

predicate func_1(Variable vargp_261) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="len"
		and target_1.getQualifier().(VariableAccess).getTarget()=vargp_261)
}

from Function func, Variable vargp_261, Variable vdirfhp_263, Variable vnewfhp_264, Variable vattrs_266, Variable vtype_271, Variable vrdev_273, Parameter vrqstp_259
where
func_0(vargp_261, vdirfhp_263, vnewfhp_264, vattrs_266, vtype_271, vrdev_273, vrqstp_259)
and func_1(vargp_261)
and vargp_261.getType().hasName("nfsd_createargs *")
and vdirfhp_263.getType().hasName("svc_fh *")
and vnewfhp_264.getType().hasName("svc_fh *")
and vattrs_266.getType().hasName("nfsd_attrs")
and vtype_271.getType().hasName("int")
and vrdev_273.getType().hasName("dev_t")
and vrqstp_259.getType().hasName("svc_rqst *")
and vargp_261.getParentScope+() = func
and vdirfhp_263.getParentScope+() = func
and vnewfhp_264.getParentScope+() = func
and vattrs_266.getParentScope+() = func
and vtype_271.getParentScope+() = func
and vrdev_273.getParentScope+() = func
and vrqstp_259.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
