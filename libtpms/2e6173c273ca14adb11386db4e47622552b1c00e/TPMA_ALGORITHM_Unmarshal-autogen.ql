/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMA_ALGORITHM_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMA-ALGORITHM-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMA_ALGORITHM_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_452, BitwiseAndExpr target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_452
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMA_ALGORITHM")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1)
}

predicate func_1(Parameter vtarget_452, BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_452
		and target_1.getRightOperand().(Literal).getValue()="4294965488"
}

from Function func, Parameter vtarget_452, BitwiseAndExpr target_1
where
not func_0(vtarget_452, target_1)
and func_1(vtarget_452, target_1)
and vtarget_452.getType().hasName("TPMA_ALGORITHM *")
and vtarget_452.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
