/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMI_RH_ACT_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMI-RH-ACT-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMI_RH_ACT_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_1084, VariableAccess target_1, LogicalOrExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1084
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMI_RH_ACT")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable visNotACT_1092, VariableAccess target_1) {
		target_1.getTarget()=visNotACT_1092
}

predicate func_2(Parameter vtarget_1084, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1084
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1073742096"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1084
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1073742111"
}

from Function func, Parameter vtarget_1084, Variable visNotACT_1092, VariableAccess target_1, LogicalOrExpr target_2
where
not func_0(vtarget_1084, target_1, target_2)
and func_1(visNotACT_1092, target_1)
and func_2(vtarget_1084, target_2)
and vtarget_1084.getType().hasName("TPMI_RH_ACT *")
and visNotACT_1092.getType().hasName("BOOL")
and vtarget_1084.getParentScope+() = func
and visNotACT_1092.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
