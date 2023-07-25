/**
 * @name krb5-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-verify_logonname
 * @id cpp/krb5/b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac/verify-logonname
 * @description krb5-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-lib/krb5/pac.c-verify_logonname CVE-2022-42898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlogon_name_930, ExprStmt target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="offset"
		and target_0.getQualifier().(VariableAccess).getTarget()=vlogon_name_930
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlogon_name_930, VariableAccess target_1) {
		target_1.getTarget()=vlogon_name_930
}

predicate func_2(Parameter vlogon_name_930, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="offset_lo"
		and target_2.getQualifier().(VariableAccess).getTarget()=vlogon_name_930
}

predicate func_3(Parameter vlogon_name_930, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("krb5_storage_from_readonly_mem")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset_lo"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlogon_name_930
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buffersize"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlogon_name_930
}

from Function func, Parameter vlogon_name_930, VariableAccess target_1, PointerFieldAccess target_2, ExprStmt target_3
where
not func_0(vlogon_name_930, target_3)
and func_1(vlogon_name_930, target_1)
and func_2(vlogon_name_930, target_2)
and func_3(vlogon_name_930, target_3)
and vlogon_name_930.getType().hasName("const PAC_INFO_BUFFER *")
and vlogon_name_930.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
