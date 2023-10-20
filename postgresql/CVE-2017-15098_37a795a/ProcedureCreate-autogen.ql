/**
 * @name postgresql-37a795a60-ProcedureCreate
 * @id cpp/postgresql/37a795a60/ProcedureCreate
 * @description postgresql-37a795a60-src/backend/catalog/pg_proc.c-ProcedureCreate CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vparameterTypes_84, FunctionCall target_0) {
		target_0.getTarget().hasName("typeidTypeRelid")
		and not target_0.getTarget().hasName("typeOrDomainTypeRelid")
		and target_0.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="values"
		and target_0.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparameterTypes_84
		and target_0.getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Oid")
}

from Function func, Parameter vparameterTypes_84, FunctionCall target_0
where
func_0(vparameterTypes_84, target_0)
and vparameterTypes_84.getType().hasName("oidvector *")
and vparameterTypes_84.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
