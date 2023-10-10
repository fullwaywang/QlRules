/**
 * @name postgresql-37a795a60-ExecEvalWholeRowVar
 * @id cpp/postgresql/37a795a60/ExecEvalWholeRowVar
 * @description postgresql-37a795a60-src/backend/executor/execExprInterp.c-ExecEvalWholeRowVar CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvariable_3404, FunctionCall target_0) {
		target_0.getTarget().hasName("lookup_rowtype_tupdesc")
		and not target_0.getTarget().hasName("lookup_rowtype_tupdesc_domain")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="vartype"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_3404
		and target_0.getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleDesc")
}

from Function func, Variable vvariable_3404, FunctionCall target_0
where
func_0(vvariable_3404, target_0)
and vvariable_3404.getType().hasName("Var *")
and vvariable_3404.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
