/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-boottime_show
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/boottime-show
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-boottime_show CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_412, Variable vdefs_414) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("snprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_412
		and target_0.getArgument(1).(Literal).getValue()="12"
		and target_0.getArgument(2).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(3).(ValueFieldAccess).getTarget().getName()="boottime"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdefs_414)
}

from Function func, Parameter vbuf_412, Variable vdefs_414
where
func_0(vbuf_412, vdefs_414)
and vbuf_412.getType().hasName("char *")
and vdefs_414.getType().hasName("mrvl_mesh_defaults")
and vbuf_412.getParentScope+() = func
and vdefs_414.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
