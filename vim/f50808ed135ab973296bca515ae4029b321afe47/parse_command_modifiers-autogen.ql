/**
 * @name vim-f50808ed135ab973296bca515ae4029b321afe47-parse_command_modifiers
 * @id cpp/vim/f50808ed135ab973296bca515ae4029b321afe47/parse-command-modifiers
 * @description vim-f50808ed135ab973296bca515ae4029b321afe47-src/ex_docmd.c-parse_command_modifiers CVE-2022-1381
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="5"
		and not target_0.getValue()="0"
		and target_0.getParent().(AssignPointerSubExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerSubExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(LogicalAndExpr target_8, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vcmd_start_2786, RelationalOperation target_9, PointerArithmeticOperation target_10) {
	exists(IfStmt target_2 |
		target_2.getCondition().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char_u *")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcmd_start_2786
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("size_t")
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strcpy")
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("char_u *")
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="'<,'>+"
		and target_2.getElse() instanceof BlockStmt
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter veap_2781, RelationalOperation target_9) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getType().hasName("int")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="'<,'>+"
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char_u *")
		and target_3.getParent().(IfStmt).getCondition()=target_9)
}

/*predicate func_4(Parameter veap_2781, PointerArithmeticOperation target_12) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_4.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_4.getRValue().(VariableAccess).getType().hasName("char_u *")
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_5(Variable vcmd_start_2786, Parameter veap_2781, RelationalOperation target_9, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vcmd_start_2786
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="5"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcmd_start_2786
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vcmd_start_2786
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignPointerSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignPointerSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignPointerSubExpr).getRValue().(Literal).getValue()="5"
		and target_5.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_5.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_5.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_5.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_5.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=":'<,'>"
		and target_5.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_5.getParent().(IfStmt).getCondition()=target_9
}

predicate func_6(Parameter veap_2781, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="cmd"
		and target_6.getQualifier().(VariableAccess).getTarget()=veap_2781
}

predicate func_7(Parameter veap_2781, AssignPointerSubExpr target_7) {
		target_7.getLValue().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_7.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_7.getRValue() instanceof Literal
}

predicate func_8(Parameter veap_2781, LogicalAndExpr target_8) {
		target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("getline_equal")
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="getline"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cookie"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("getline_equal")
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="getline"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cookie"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="ml_line_count"
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
}

predicate func_9(Variable vcmd_start_2786, Parameter veap_2781, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_9.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vcmd_start_2786
}

predicate func_10(Variable vcmd_start_2786, PointerArithmeticOperation target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vcmd_start_2786
		and target_10.getRightOperand().(Literal).getValue()="5"
}

predicate func_12(Parameter veap_2781, PointerArithmeticOperation target_12) {
		target_12.getLeftOperand().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2781
		and target_12.getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vcmd_start_2786, Parameter veap_2781, Literal target_0, BlockStmt target_5, PointerFieldAccess target_6, AssignPointerSubExpr target_7, LogicalAndExpr target_8, RelationalOperation target_9, PointerArithmeticOperation target_10, PointerArithmeticOperation target_12
where
func_0(func, target_0)
and not func_1(target_8, func)
and not func_2(vcmd_start_2786, target_9, target_10)
and not func_3(veap_2781, target_9)
and func_5(vcmd_start_2786, veap_2781, target_9, target_5)
and func_6(veap_2781, target_6)
and func_7(veap_2781, target_7)
and func_8(veap_2781, target_8)
and func_9(vcmd_start_2786, veap_2781, target_9)
and func_10(vcmd_start_2786, target_10)
and func_12(veap_2781, target_12)
and vcmd_start_2786.getType().hasName("char_u *")
and veap_2781.getType().hasName("exarg_T *")
and vcmd_start_2786.getParentScope+() = func
and veap_2781.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
