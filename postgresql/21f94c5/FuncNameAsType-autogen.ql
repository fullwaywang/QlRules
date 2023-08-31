/**
 * @name postgresql-21f94c5-FuncNameAsType
 * @id cpp/postgresql/21f94c5/FuncNameAsType
 * @description postgresql-21f94c5-src/backend/parser/parse_func.c-FuncNameAsType CVE-2019-10208
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfuncname_1875, FunctionCall target_0) {
		target_0.getTarget().hasName("LookupTypeName")
		and not target_0.getTarget().hasName("LookupTypeNameExtended")
		and target_0.getArgument(0).(Literal).getValue()="0"
		and target_0.getArgument(1).(FunctionCall).getTarget().hasName("makeTypeNameFromNameList")
		and target_0.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfuncname_1875
		and target_0.getArgument(2).(Literal).getValue()="0"
		and target_0.getArgument(3).(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Type")
}

from Function func, Parameter vfuncname_1875, FunctionCall target_0
where
func_0(vfuncname_1875, target_0)
and vfuncname_1875.getType().hasName("List *")
and vfuncname_1875.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
