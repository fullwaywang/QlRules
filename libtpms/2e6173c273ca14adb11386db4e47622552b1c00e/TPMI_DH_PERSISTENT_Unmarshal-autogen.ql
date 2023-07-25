/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMI_DH_PERSISTENT_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMI-DH-PERSISTENT-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMI_DH_PERSISTENT_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_611, VariableAccess target_1, LogicalOrExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_611
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMI_DH_PERSISTENT")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable visNotPersistent_619, VariableAccess target_1) {
		target_1.getTarget()=visNotPersistent_619
}

predicate func_2(Parameter vtarget_611, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_611
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="2164260864"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_611
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="2181038079"
}

from Function func, Variable visNotPersistent_619, Parameter vtarget_611, VariableAccess target_1, LogicalOrExpr target_2
where
not func_0(vtarget_611, target_1, target_2)
and func_1(visNotPersistent_619, target_1)
and func_2(vtarget_611, target_2)
and visNotPersistent_619.getType().hasName("BOOL")
and vtarget_611.getType().hasName("TPMI_DH_PERSISTENT *")
and visNotPersistent_619.getParentScope+() = func
and vtarget_611.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
