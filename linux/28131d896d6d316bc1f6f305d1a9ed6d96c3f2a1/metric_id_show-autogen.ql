/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-metric_id_show
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/metric-id-show
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-metric_id_show CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_660, Variable vdefs_662) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("snprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_660
		and target_0.getArgument(1).(Literal).getValue()="5"
		and target_0.getArgument(2).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(3).(ValueFieldAccess).getTarget().getName()="active_metric_id"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="val"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="meshie"
		and target_0.getArgument(3).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdefs_662)
}

from Function func, Parameter vbuf_660, Variable vdefs_662
where
func_0(vbuf_660, vdefs_662)
and vbuf_660.getType().hasName("char *")
and vdefs_662.getType().hasName("mrvl_mesh_defaults")
and vbuf_660.getParentScope+() = func
and vdefs_662.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
