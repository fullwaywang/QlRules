/**
 * @name vim-11977f917506d950b7e0cae558bd9189260b253b-same_leader
 * @id cpp/vim/11977f917506d950b7e0cae558bd9189260b253b/same-leader
 * @description vim-11977f917506d950b7e0cae558bd9189260b253b-src/textformat.c-same_leader CVE-2023-0433
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(EqualityOperation target_7, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char_u *")
		and target_1.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(EqualityOperation target_7, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char_u *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vleader1_len_530, EqualityOperation target_8, EqualityOperation target_9, LogicalAndExpr target_10) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vleader1_len_530
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vlnum_529, FunctionCall target_4) {
		target_4.getTarget().hasName("ml_get")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vlnum_529
}

predicate func_5(Parameter vleader1_len_530, VariableAccess target_5) {
		target_5.getTarget()=vleader1_len_530
}

predicate func_6(Parameter vleader1_len_530, ReturnStmt target_11, PointerDereferenceExpr target_6) {
		target_6.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof FunctionCall
		and target_6.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vleader1_len_530
		and target_6.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_6.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_11
}

predicate func_7(EqualityOperation target_7) {
		target_7.getAnOperand() instanceof PointerDereferenceExpr
		and target_7.getAnOperand().(Literal).getValue()="0"
}

predicate func_8(EqualityOperation target_8) {
		target_8.getAnOperand().(Literal).getValue()="115"
}

predicate func_9(Parameter vleader1_len_530, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vleader1_len_530
		and target_9.getAnOperand().(Literal).getValue()="0"
}

predicate func_10(Parameter vleader1_len_530, LogicalAndExpr target_10) {
		target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vleader1_len_530
}

predicate func_11(ReturnStmt target_11) {
		target_11.getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vlnum_529, Parameter vleader1_len_530, FunctionCall target_4, VariableAccess target_5, PointerDereferenceExpr target_6, EqualityOperation target_7, EqualityOperation target_8, EqualityOperation target_9, LogicalAndExpr target_10, ReturnStmt target_11
where
not func_1(target_7, func)
and not func_2(target_7, func)
and not func_3(vleader1_len_530, target_8, target_9, target_10)
and func_4(vlnum_529, target_4)
and func_5(vleader1_len_530, target_5)
and func_6(vleader1_len_530, target_11, target_6)
and func_7(target_7)
and func_8(target_8)
and func_9(vleader1_len_530, target_9)
and func_10(vleader1_len_530, target_10)
and func_11(target_11)
and vlnum_529.getType().hasName("linenr_T")
and vleader1_len_530.getType().hasName("int")
and vlnum_529.getParentScope+() = func
and vleader1_len_530.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
