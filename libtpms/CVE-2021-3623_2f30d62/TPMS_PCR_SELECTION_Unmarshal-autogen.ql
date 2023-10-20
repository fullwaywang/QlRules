/**
 * @name libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-TPMS_PCR_SELECTION_Unmarshal
 * @id cpp/libtpms/2f30d620d3c053f20d38b54bf76ac0907821d263/TPMS-PCR-SELECTION-Unmarshal
 * @description libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-src/tpm2/Unmarshal.c-TPMS_PCR_SELECTION_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_1675, LogicalOrExpr target_1, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeofSelect"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1675
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtarget_1675, LogicalOrExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="sizeofSelect"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1675
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="3"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="sizeofSelect"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1675
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="3"
}

predicate func_2(Parameter vtarget_1675, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Array_Unmarshal")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pcrSelect"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1675
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sizeofSelect"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_1675
}

from Function func, Parameter vtarget_1675, LogicalOrExpr target_1, ExprStmt target_2
where
not func_0(vtarget_1675, target_1, target_2)
and func_1(vtarget_1675, target_1)
and func_2(vtarget_1675, target_2)
and vtarget_1675.getType().hasName("TPMS_PCR_SELECTION *")
and vtarget_1675.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
