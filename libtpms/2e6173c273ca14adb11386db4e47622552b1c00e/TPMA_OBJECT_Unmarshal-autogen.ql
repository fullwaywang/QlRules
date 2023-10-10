/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMA_OBJECT_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMA-OBJECT-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMA_OBJECT_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_470, BitwiseAndExpr target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_470
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMA_OBJECT")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1)
}

predicate func_1(Parameter vtarget_470, BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_470
		and target_1.getRightOperand().(Literal).getValue()="4293980937"
}

from Function func, Parameter vtarget_470, BitwiseAndExpr target_1
where
not func_0(vtarget_470, target_1)
and func_1(vtarget_470, target_1)
and vtarget_470.getType().hasName("TPMA_OBJECT *")
and vtarget_470.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
