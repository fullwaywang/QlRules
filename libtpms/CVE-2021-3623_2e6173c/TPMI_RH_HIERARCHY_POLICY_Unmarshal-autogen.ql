/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMI_RH_HIERARCHY_POLICY_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMI-RH-HIERARCHY-POLICY-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMI_RH_HIERARCHY_POLICY_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_879, VariableAccess target_1, LogicalOrExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_879
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMI_RH_HIERARCHY_POLICY")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable visNotHP_895, VariableAccess target_1) {
		target_1.getTarget()=visNotHP_895
}

predicate func_2(Parameter vtarget_879, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_879
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1073742096"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_879
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1073742111"
}

from Function func, Variable visNotHP_895, Parameter vtarget_879, VariableAccess target_1, LogicalOrExpr target_2
where
not func_0(vtarget_879, target_1, target_2)
and func_1(visNotHP_895, target_1)
and func_2(vtarget_879, target_2)
and visNotHP_895.getType().hasName("BOOL")
and vtarget_879.getType().hasName("TPMI_RH_HIERARCHY_POLICY *")
and visNotHP_895.getParentScope+() = func
and vtarget_879.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
