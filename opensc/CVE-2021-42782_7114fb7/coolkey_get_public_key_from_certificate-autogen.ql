/**
 * @name opensc-7114fb71-coolkey_get_public_key_from_certificate
 * @id cpp/opensc/7114fb71/coolkey-get-public-key-from-certificate
 * @description opensc-7114fb71-src/libopensc/pkcs15-coolkey.c-coolkey_get_public_key_from_certificate CVE-2021-42782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcert_info_423, AddressOfExpr target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("memset")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcert_info_423
		and target_0.getArgument(1) instanceof Literal
		and target_0.getArgument(2).(SizeofExprOperator).getValue()="352"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcert_info_423, VariableAccess target_1) {
		target_1.getTarget()=vcert_info_423
}

predicate func_3(Variable vcert_info_423, AssignExpr target_3) {
		target_3.getLValue().(ValueFieldAccess).getTarget().getName()="value"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcert_info_423
		and target_3.getRValue() instanceof Literal
}

predicate func_4(Variable vcert_info_423, AddressOfExpr target_4) {
		target_4.getOperand().(ValueFieldAccess).getTarget().getName()="value"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcert_info_423
}

from Function func, Variable vcert_info_423, VariableAccess target_1, AssignExpr target_3, AddressOfExpr target_4
where
not func_0(vcert_info_423, target_4)
and func_1(vcert_info_423, target_1)
and func_3(vcert_info_423, target_3)
and func_4(vcert_info_423, target_4)
and vcert_info_423.getType().hasName("sc_pkcs15_cert_info_t")
and vcert_info_423.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
