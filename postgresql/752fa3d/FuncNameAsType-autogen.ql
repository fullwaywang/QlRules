/**
 * @name postgresql-752fa3d-FuncNameAsType
 * @id cpp/postgresql/752fa3d/FuncNameAsType
 * @description postgresql-752fa3d-src/backend/parser/parse_func.c-FuncNameAsType CVE-2019-10208
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfuncname_1741, FunctionCall target_0) {
		target_0.getTarget().hasName("LookupTypeName")
		and not target_0.getTarget().hasName("LookupTypeNameExtended")
		and target_0.getArgument(0).(Literal).getValue()="0"
		and target_0.getArgument(1).(FunctionCall).getTarget().hasName("makeTypeNameFromNameList")
		and target_0.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfuncname_1741
		and target_0.getArgument(2).(Literal).getValue()="0"
		and target_0.getArgument(3).(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Type")
}

from Function func, Parameter vfuncname_1741, FunctionCall target_0
where
func_0(vfuncname_1741, target_0)
and vfuncname_1741.getType().hasName("List *")
and vfuncname_1741.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
