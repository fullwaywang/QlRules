/**
 * @name samba-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-verify_checksum
 * @id cpp/samba/b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac/verify-checksum
 * @description samba-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-lib/krb5/pac.c-verify_checksum CVE-2022-42898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsig_568, ExprStmt target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="offset"
		and target_0.getQualifier().(VariableAccess).getTarget()=vsig_568
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsig_568, VariableAccess target_1) {
		target_1.getTarget()=vsig_568
}

predicate func_2(Parameter vsig_568, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="offset_lo"
		and target_2.getQualifier().(VariableAccess).getTarget()=vsig_568
}

predicate func_3(Parameter vsig_568, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("krb5_storage_from_mem")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset_lo"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsig_568
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buffersize"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsig_568
}

from Function func, Parameter vsig_568, VariableAccess target_1, PointerFieldAccess target_2, ExprStmt target_3
where
not func_0(vsig_568, target_3)
and func_1(vsig_568, target_1)
and func_2(vsig_568, target_2)
and func_3(vsig_568, target_3)
and vsig_568.getType().hasName("const PAC_INFO_BUFFER *")
and vsig_568.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
