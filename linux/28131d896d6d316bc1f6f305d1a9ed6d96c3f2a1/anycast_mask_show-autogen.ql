/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-anycast_mask_show
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/anycast-mask-show
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-anycast_mask_show CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_160, Variable vmesh_access_163) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("snprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_160
		and target_0.getArgument(1).(Literal).getValue()="12"
		and target_0.getArgument(2).(StringLiteral).getValue()="0x%X\n"
		and target_0.getArgument(3).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_0.getArgument(3).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmesh_access_163
		and target_0.getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

from Function func, Parameter vbuf_160, Variable vmesh_access_163
where
func_0(vbuf_160, vmesh_access_163)
and vbuf_160.getType().hasName("char *")
and vmesh_access_163.getType().hasName("cmd_ds_mesh_access")
and vbuf_160.getParentScope+() = func
and vmesh_access_163.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
