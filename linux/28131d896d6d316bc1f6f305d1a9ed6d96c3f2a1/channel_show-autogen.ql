/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-channel_show
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/channel-show
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-channel_show CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_472, Variable vdefs_474) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("snprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_472
		and target_0.getArgument(1).(Literal).getValue()="12"
		and target_0.getArgument(2).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(3).(ValueFieldAccess).getTarget().getName()="channel"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdefs_474)
}

from Function func, Parameter vbuf_472, Variable vdefs_474
where
func_0(vbuf_472, vdefs_474)
and vbuf_472.getType().hasName("char *")
and vdefs_474.getType().hasName("mrvl_mesh_defaults")
and vbuf_472.getParentScope+() = func
and vdefs_474.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
