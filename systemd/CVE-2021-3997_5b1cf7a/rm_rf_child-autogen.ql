/**
 * @name systemd-5b1cf7a9be37e20133c0208005274ce4a5b5c6a1-rm_rf_child
 * @id cpp/systemd/5b1cf7a9be37e20133c0208005274ce4a5b5c6a1/rm-rf-child
 * @description systemd-5b1cf7a9be37e20133c0208005274ce4a5b5c6a1-src/shared/rm-rf.c-rm_rf_child CVE-2021-3997
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfd_322, Parameter vname_322, Parameter vflags_322, FunctionCall target_0) {
		target_0.getTarget().hasName("rm_rf_children_inner")
		and not target_0.getTarget().hasName("rm_rf_inner_child")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vfd_322
		and target_0.getArgument(1).(VariableAccess).getTarget()=vname_322
		and target_0.getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_0.getArgument(3).(VariableAccess).getTarget()=vflags_322
		and target_0.getArgument(4).(Literal).getValue()="0"
}

from Function func, Parameter vfd_322, Parameter vname_322, Parameter vflags_322, FunctionCall target_0
where
func_0(vfd_322, vname_322, vflags_322, target_0)
and vfd_322.getType().hasName("int")
and vname_322.getType().hasName("const char *")
and vflags_322.getType().hasName("RemoveFlags")
and vfd_322.getParentScope+() = func
and vname_322.getParentScope+() = func
and vflags_322.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
