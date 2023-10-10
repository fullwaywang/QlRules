/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-bootflag_show
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/bootflag-show
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-bootflag_show CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_362, Variable vdefs_364) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("snprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_362
		and target_0.getArgument(1).(Literal).getValue()="12"
		and target_0.getArgument(2).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(3).(ValueFieldAccess).getTarget().getName()="bootflag"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdefs_364)
}

from Function func, Parameter vbuf_362, Variable vdefs_364
where
func_0(vbuf_362, vdefs_364)
and vbuf_362.getType().hasName("char *")
and vdefs_364.getType().hasName("mrvl_mesh_defaults")
and vbuf_362.getParentScope+() = func
and vdefs_364.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
