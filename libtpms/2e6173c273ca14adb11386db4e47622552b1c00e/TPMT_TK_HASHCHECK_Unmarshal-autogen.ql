/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMT_TK_HASHCHECK_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMT-TK-HASHCHECK-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMT_TK_HASHCHECK_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_1775, EqualityOperation target_1, AddressOfExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tag"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1775
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPM_ST")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtarget_1775, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="tag"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1775
		and target_1.getAnOperand().(Literal).getValue()="32804"
}

predicate func_2(Parameter vtarget_1775, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="hierarchy"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1775
}

from Function func, Parameter vtarget_1775, EqualityOperation target_1, AddressOfExpr target_2
where
not func_0(vtarget_1775, target_1, target_2)
and func_1(vtarget_1775, target_1)
and func_2(vtarget_1775, target_2)
and vtarget_1775.getType().hasName("TPMT_TK_HASHCHECK *")
and vtarget_1775.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
