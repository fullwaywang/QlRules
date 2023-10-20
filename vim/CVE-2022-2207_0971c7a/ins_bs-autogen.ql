/**
 * @name vim-0971c7a4e537ea120a6bb2195960be8d0815e97b-ins_bs
 * @id cpp/vim/0971c7a4e537ea120a6bb2195960be8d0815e97b/ins-bs
 * @description vim-0971c7a4e537ea120a6bb2195960be8d0815e97b-src/edit.c-ins_bs CVE-2022-2207
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcurwin, AddressOfExpr target_2, LogicalAndExpr target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(FunctionCall).getTarget().hasName("ml_get_cursor")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(CommaExpr).getRightOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(CommaExpr).getRightOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="9"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vvcol_4155, Variable vwant_vcol_4156, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vvcol_4155
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vwant_vcol_4156
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getLeftOperand().(FunctionCall).getTarget().hasName("ml_get_cursor")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(CommaExpr).getRightOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(CommaExpr).getRightOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="9"
}

predicate func_2(Variable vcurwin, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

predicate func_3(Variable vcurwin, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="col"
}

from Function func, Variable vcurwin, Variable vvcol_4155, Variable vwant_vcol_4156, RelationalOperation target_1, AddressOfExpr target_2, LogicalAndExpr target_3
where
not func_0(vcurwin, target_2, target_3)
and func_1(vvcol_4155, vwant_vcol_4156, target_1)
and func_2(vcurwin, target_2)
and func_3(vcurwin, target_3)
and vcurwin.getType().hasName("win_T *")
and vvcol_4155.getType().hasName("colnr_T")
and vwant_vcol_4156.getType().hasName("colnr_T")
and not vcurwin.getParentScope+() = func
and vvcol_4155.getParentScope+() = func
and vwant_vcol_4156.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
