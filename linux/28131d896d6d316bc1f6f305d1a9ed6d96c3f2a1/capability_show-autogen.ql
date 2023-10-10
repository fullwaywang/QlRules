/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-capability_show
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/capability-show
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-capability_show CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_722, Variable vdefs_724) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("snprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_722
		and target_0.getArgument(1).(Literal).getValue()="5"
		and target_0.getArgument(2).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(3).(ValueFieldAccess).getTarget().getName()="mesh_capability"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="val"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="meshie"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdefs_724)
}

from Function func, Parameter vbuf_722, Variable vdefs_724
where
func_0(vbuf_722, vdefs_724)
and vbuf_722.getType().hasName("char *")
and vdefs_724.getType().hasName("mrvl_mesh_defaults")
and vbuf_722.getParentScope+() = func
and vdefs_724.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
