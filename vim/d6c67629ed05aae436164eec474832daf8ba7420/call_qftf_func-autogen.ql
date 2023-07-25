/**
 * @name vim-d6c67629ed05aae436164eec474832daf8ba7420-call_qftf_func
 * @id cpp/vim/d6c67629ed05aae436164eec474832daf8ba7420/call-qftf-func
 * @description vim-d6c67629ed05aae436164eec474832daf8ba7420-src/quickfix.c-call_qftf_func CVE-2022-2982
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_2(EqualityOperation target_4, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_3))
}

predicate func_4(Variable vcb_4675, BlockStmt target_6, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="cb_name"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcb_4675
		and target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_6
}

predicate func_5(Variable vd_4686, ReturnStmt target_7, EqualityOperation target_5) {
		target_5.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vd_4686
		and target_5.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dict_alloc_lock")
		and target_5.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_5.getAnOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen()=target_7
}

predicate func_6(Variable vd_4686, BlockStmt target_6) {
		target_6.getStmt(3).(IfStmt).getCondition() instanceof EqualityOperation
		and target_6.getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_6.getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dict_add_number")
		and target_6.getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vd_4686
		and target_6.getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="quickfix"
		and target_6.getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="qfl_type"
}

predicate func_7(ReturnStmt target_7) {
		target_7.getExpr().(Literal).getValue()="0"
}

from Function func, Variable vcb_4675, Variable vd_4686, EqualityOperation target_4, EqualityOperation target_5, BlockStmt target_6, ReturnStmt target_7
where
not func_1(func)
and not func_2(target_4, func)
and not func_3(func)
and func_4(vcb_4675, target_6, target_4)
and func_5(vd_4686, target_7, target_5)
and func_6(vd_4686, target_6)
and func_7(target_7)
and vcb_4675.getType().hasName("callback_T *")
and vd_4686.getType().hasName("dict_T *")
and vcb_4675.getParentScope+() = func
and vd_4686.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
