/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMA_SESSION_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMA-SESSION-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMA_SESSION_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_488, BitwiseAndExpr target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_488
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMA_SESSION")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1)
}

predicate func_1(Parameter vtarget_488, BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_488
		and target_1.getRightOperand().(Literal).getValue()="24"
}

from Function func, Parameter vtarget_488, BitwiseAndExpr target_1
where
not func_0(vtarget_488, target_1)
and func_1(vtarget_488, target_1)
and vtarget_488.getType().hasName("TPMA_SESSION *")
and vtarget_488.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
