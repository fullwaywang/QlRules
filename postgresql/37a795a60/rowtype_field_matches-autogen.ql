/**
 * @name postgresql-37a795a60-rowtype_field_matches
 * @id cpp/postgresql/37a795a60/rowtype-field-matches
 * @description postgresql-37a795a60-src/backend/optimizer/util/clauses.c-rowtype_field_matches CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrowtypeid_2361, FunctionCall target_0) {
		target_0.getTarget().hasName("lookup_rowtype_tupdesc")
		and not target_0.getTarget().hasName("lookup_rowtype_tupdesc_domain")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vrowtypeid_2361
		and target_0.getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleDesc")
}

from Function func, Parameter vrowtypeid_2361, FunctionCall target_0
where
func_0(vrowtypeid_2361, target_0)
and vrowtypeid_2361.getType().hasName("Oid")
and vrowtypeid_2361.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
