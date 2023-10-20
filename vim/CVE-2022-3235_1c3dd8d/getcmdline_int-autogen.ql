/**
 * @name vim-1c3dd8ddcba63c1af5112e567215b3cec2de11d0-getcmdline_int
 * @id cpp/vim/1c3dd8ddcba63c1af5112e567215b3cec2de11d0/getcmdline-int
 * @description vim-1c3dd8ddcba63c1af5112e567215b3cec2de11d0-src/ex_getln.c-getcmdline_int CVE-2022-3235
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcurbuf, LogicalOrExpr target_5, ExprStmt target_6) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("buf_T *")
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcurbuf
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vb_im_ptr_1589, EqualityOperation target_7, LogicalAndExpr target_8) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(FunctionCall).getTarget().hasName("buf_valid")
		and target_1.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("buf_T *")
		and target_1.getThen().(VariableAccess).getTarget()=vb_im_ptr_1589
		and target_1.getElse().(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cmdline_toggle_langmap")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_im_ptr_1589
		and target_7.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(VariableAccess).getLocation())
		and target_1.getThen().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vb_im_ptr_1589, ExprStmt target_9) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getAnOperand().(FunctionCall).getTarget().hasName("buf_valid")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("buf_T *")
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vb_im_ptr_1589
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_9)
}

predicate func_3(Variable vb_im_ptr_1589, ExprStmt target_9, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vb_im_ptr_1589
		and target_3.getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vb_im_ptr_1589
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_4(Variable vb_im_ptr_1589, VariableAccess target_4) {
		target_4.getTarget()=vb_im_ptr_1589
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cmdline_toggle_langmap")
}

predicate func_5(LogicalOrExpr target_5) {
		target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="63"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="64"
}

predicate func_6(Variable vcurbuf, Variable vb_im_ptr_1589, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb_im_ptr_1589
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="b_p_imsearch"
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
}

predicate func_7(Variable vb_im_ptr_1589, EqualityOperation target_7) {
		target_7.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vb_im_ptr_1589
		and target_7.getAnOperand().(Literal).getValue()="2"
}

predicate func_8(Variable vb_im_ptr_1589, LogicalAndExpr target_8) {
		target_8.getAnOperand() instanceof EqualityOperation
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vb_im_ptr_1589
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_9(Variable vb_im_ptr_1589, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("im_save_status")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_im_ptr_1589
}

from Function func, Variable vcurbuf, Variable vb_im_ptr_1589, EqualityOperation target_3, VariableAccess target_4, LogicalOrExpr target_5, ExprStmt target_6, EqualityOperation target_7, LogicalAndExpr target_8, ExprStmt target_9
where
not func_0(vcurbuf, target_5, target_6)
and not func_1(vb_im_ptr_1589, target_7, target_8)
and not func_2(vb_im_ptr_1589, target_9)
and func_3(vb_im_ptr_1589, target_9, target_3)
and func_4(vb_im_ptr_1589, target_4)
and func_5(target_5)
and func_6(vcurbuf, vb_im_ptr_1589, target_6)
and func_7(vb_im_ptr_1589, target_7)
and func_8(vb_im_ptr_1589, target_8)
and func_9(vb_im_ptr_1589, target_9)
and vcurbuf.getType().hasName("buf_T *")
and vb_im_ptr_1589.getType().hasName("long *")
and not vcurbuf.getParentScope+() = func
and vb_im_ptr_1589.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
