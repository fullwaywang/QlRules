/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMI_RH_NV_INDEX_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMI-RH-NV-INDEX-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMI_RH_NV_INDEX_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_1046, VariableAccess target_1, LogicalOrExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1046
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMI_RH_NV_INDEX")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable visNotNv_1054, VariableAccess target_1) {
		target_1.getTarget()=visNotNv_1054
}

predicate func_2(Parameter vtarget_1046, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1046
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="16777216"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1046
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="33554431"
}

from Function func, Parameter vtarget_1046, Variable visNotNv_1054, VariableAccess target_1, LogicalOrExpr target_2
where
not func_0(vtarget_1046, target_1, target_2)
and func_1(visNotNv_1054, target_1)
and func_2(vtarget_1046, target_2)
and vtarget_1046.getType().hasName("TPMI_RH_NV_INDEX *")
and visNotNv_1054.getType().hasName("BOOL")
and vtarget_1046.getParentScope+() = func
and visNotNv_1054.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
