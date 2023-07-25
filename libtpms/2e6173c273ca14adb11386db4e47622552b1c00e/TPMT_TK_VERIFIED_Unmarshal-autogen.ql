/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMT_TK_VERIFIED_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMT-TK-VERIFIED-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMT_TK_VERIFIED_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_1726, EqualityOperation target_1, AddressOfExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tag"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1726
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPM_ST")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtarget_1726, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="tag"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1726
		and target_1.getAnOperand().(Literal).getValue()="32802"
}

predicate func_2(Parameter vtarget_1726, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="hierarchy"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1726
}

from Function func, Parameter vtarget_1726, EqualityOperation target_1, AddressOfExpr target_2
where
not func_0(vtarget_1726, target_1, target_2)
and func_1(vtarget_1726, target_1)
and func_2(vtarget_1726, target_2)
and vtarget_1726.getType().hasName("TPMT_TK_VERIFIED *")
and vtarget_1726.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
