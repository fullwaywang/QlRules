/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMA_NV_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMA-NV-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMA_NV_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_4221, BitwiseAndExpr target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_4221
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMA_NV")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1)
}

predicate func_1(Parameter vtarget_4221, BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_4221
		and target_1.getRightOperand().(BitwiseOrExpr).getValue()="32506624"
}

from Function func, Parameter vtarget_4221, BitwiseAndExpr target_1
where
not func_0(vtarget_4221, target_1)
and func_1(vtarget_4221, target_1)
and vtarget_4221.getType().hasName("TPMA_NV *")
and vtarget_4221.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
