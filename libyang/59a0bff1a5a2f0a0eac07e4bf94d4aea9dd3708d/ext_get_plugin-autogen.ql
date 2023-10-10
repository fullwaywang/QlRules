/**
 * @name libyang-59a0bff1a5a2f0a0eac07e4bf94d4aea9dd3708d-ext_get_plugin
 * @id cpp/libyang/59a0bff1a5a2f0a0eac07e4bf94d4aea9dd3708d/ext-get-plugin
 * @description libyang-59a0bff1a5a2f0a0eac07e4bf94d4aea9dd3708d-src/plugins.c-ext_get_plugin CVE-2021-28904
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrevision_452) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vrevision_452
		and target_0.getAnOperand() instanceof NotExpr)
}

predicate func_1(Parameter vrevision_452) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vrevision_452
		and target_1.getAnOperand() instanceof NotExpr)
}

predicate func_2(Variable vu_454, Variable vext_plugins, NotExpr target_2) {
		target_2.getOperand().(ValueFieldAccess).getTarget().getName()="revision"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vext_plugins
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vu_454
}

predicate func_3(Parameter vrevision_452, Variable vu_454, Variable vext_plugins, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrevision_452
		and target_3.getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="revision"
		and target_3.getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vext_plugins
		and target_3.getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vu_454
}

from Function func, Parameter vrevision_452, Variable vu_454, Variable vext_plugins, NotExpr target_2, NotExpr target_3
where
not func_0(vrevision_452)
and not func_1(vrevision_452)
and func_2(vu_454, vext_plugins, target_2)
and func_3(vrevision_452, vu_454, vext_plugins, target_3)
and vrevision_452.getType().hasName("const char *")
and vu_454.getType().hasName("uint16_t")
and vext_plugins.getType().hasName("lyext_plugin_list *")
and vrevision_452.getParentScope+() = func
and vu_454.getParentScope+() = func
and not vext_plugins.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
