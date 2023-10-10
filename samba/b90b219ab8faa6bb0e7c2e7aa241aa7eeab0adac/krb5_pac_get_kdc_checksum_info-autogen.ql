/**
 * @name samba-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-krb5_pac_get_kdc_checksum_info
 * @id cpp/samba/b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac/krb5-pac-get-kdc-checksum-info
 * @description samba-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-lib/krb5/pac.c-krb5_pac_get_kdc_checksum_info CVE-2022-42898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsig_1774, EqualityOperation target_3, ExprStmt target_4) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="offset"
		and target_0.getQualifier().(VariableAccess).getTarget()=vsig_1774
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsig_1774, VariableAccess target_1) {
		target_1.getTarget()=vsig_1774
}

predicate func_2(Variable vsig_1774, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="offset_lo"
		and target_2.getQualifier().(VariableAccess).getTarget()=vsig_1774
}

predicate func_3(Variable vsig_1774, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vsig_1774
		and target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vsig_1774, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("krb5_storage_from_mem")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset_lo"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsig_1774
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buffersize"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsig_1774
}

from Function func, Variable vsig_1774, VariableAccess target_1, PointerFieldAccess target_2, EqualityOperation target_3, ExprStmt target_4
where
not func_0(vsig_1774, target_3, target_4)
and func_1(vsig_1774, target_1)
and func_2(vsig_1774, target_2)
and func_3(vsig_1774, target_3)
and func_4(vsig_1774, target_4)
and vsig_1774.getType().hasName("const PAC_INFO_BUFFER *")
and vsig_1774.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
